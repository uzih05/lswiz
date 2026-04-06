# -*- coding: utf-8 -*-
"""Manual binary scanner.

Detects software installed outside the RPM package manager by scanning
filesystem paths and using the parser registry for version extraction.
"""
from __future__ import absolute_import
import os
import subprocess
import stat

from lswiz.scanner.registry import get_parser, is_dedicated

# system binaries to always skip (coreutils, etc.)
SKIP_BINARIES = frozenset([
    'arch', 'base64', 'basename', 'cat', 'chgrp', 'chmod', 'chown',
    'cp', 'cut', 'date', 'dd', 'df', 'dir', 'dirname', 'du', 'echo',
    'env', 'expand', 'expr', 'factor', 'false', 'fmt', 'fold', 'groups',
    'head', 'hostid', 'hostname', 'id', 'install', 'join', 'kill',
    'link', 'ln', 'logname', 'ls', 'md5sum', 'mkdir', 'mkfifo',
    'mknod', 'mktemp', 'mv', 'nice', 'nl', 'nohup', 'nproc', 'numfmt',
    'od', 'paste', 'pathchk', 'pinky', 'pr', 'printenv', 'printf',
    'ptx', 'pwd', 'readlink', 'realpath', 'rm', 'rmdir', 'runcon',
    'sed', 'seq', 'sha1sum', 'sha256sum', 'sha512sum', 'shred', 'shuf',
    'sleep', 'sort', 'split', 'stat', 'stdbuf', 'stty', 'sum', 'sync',
    'tac', 'tail', 'tee', 'test', 'timeout', 'touch', 'tr', 'true',
    'truncate', 'tsort', 'tty', 'uname', 'unexpand', 'uniq', 'unlink',
    'uptime', 'users', 'vdir', 'wc', 'who', 'whoami', 'yes',
    # common shell/system tools
    'bash', 'sh', 'dash', 'zsh', 'csh', 'tcsh',
    'grep', 'egrep', 'fgrep', 'awk', 'gawk', 'find', 'xargs',
    'less', 'more', 'vi', 'vim', 'nano',
    'tar', 'gzip', 'gunzip', 'bzip2', 'xz', 'zip', 'unzip',
    'ssh', 'scp', 'sftp',
    'man', 'info', 'which', 'whereis', 'locate',
    'top', 'htop', 'free', 'vmstat', 'iostat',
    'ifconfig', 'ip', 'route', 'ping', 'traceroute', 'netstat',
    'mount', 'umount', 'fdisk', 'lsblk', 'blkid',
    'systemctl', 'journalctl', 'service',
    'yum', 'rpm', 'pip', 'pip3',
    'sudo', 'su', 'passwd', 'useradd', 'userdel', 'usermod',
    'crontab', 'at',
])


def scan_manual_binaries(config, logger):
    """Scan for manually installed binaries.

    Flow:
      1. Walk configured paths for executable files
      2. Filter out RPM-owned binaries
      3. Filter out known system binaries (whitelist)
      4. Extract version using dedicated or generic parser
      5. Classify result as CONFIRMED / DETECTED / UNKNOWN

    Returns:
        list: list of binary dicts with keys:
            - name (str): binary filename
            - path (str): absolute path
            - version (str): extracted version or ''
            - source (str): 'manual'
            - detection (str): CONFIRMED / DETECTED / UNKNOWN
            - cpe (str): CPE string if available
            - parser (str): parser name used
            - status (str): set later by status classifier
            - cves (list): populated later by CVE matcher
    """
    logger.info('Scanning for manually installed binaries...')

    scan_paths = config['scan'].get('manual_paths', ['/usr/local/bin'])
    candidates = _find_executables(scan_paths, logger)
    logger.info('  Found %d executable files', len(candidates))

    # filter RPM-owned
    non_rpm = _filter_non_rpm(candidates, logger)
    logger.info('  %d binaries not owned by RPM', len(non_rpm))

    # filter system binaries
    filtered = [(path, name) for path, name in non_rpm if name not in SKIP_BINARIES]
    logger.info('  %d binaries after whitelist filter', len(filtered))

    results = []
    for binary_path, binary_name in filtered:
        parser = get_parser(binary_name)
        dedicated = is_dedicated(binary_name)

        version = parser.extract_version(binary_path)
        cpe = ''
        if version and dedicated:
            cpe = parser.build_cpe(version)

        if version and cpe:
            detection = 'CONFIRMED'
        elif version:
            detection = 'DETECTED'
        else:
            detection = 'UNKNOWN'

        results.append({
            'name': binary_name,
            'path': binary_path,
            'version': version or '',
            'source': 'manual',
            'detection': detection,
            'cpe': cpe,
            'parser': type(parser).__name__,
            'status': '',
            'cves': [],
        })

        if detection == 'CONFIRMED':
            logger.info('  [CONFIRMED] %s %s (%s)', binary_name, version, cpe)
        elif detection == 'DETECTED':
            logger.info('  [DETECTED]  %s %s (no CPE)', binary_name, version)
        else:
            logger.debug('  [UNKNOWN]   %s (version extraction failed)', binary_name)

    return results


def _find_executables(paths, logger):
    """Find all executable files in given paths.

    Returns:
        list of (absolute_path, filename) tuples
    """
    executables = []
    seen = set()

    for scan_path in paths:
        if not os.path.isdir(scan_path):
            continue

        # for /opt, walk recursively; for bin dirs, list only top level
        if scan_path == '/opt':
            for root, dirs, files in os.walk(scan_path):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if fpath in seen:
                        continue
                    seen.add(fpath)
                    if _is_executable(fpath):
                        executables.append((fpath, fname))
        else:
            try:
                for fname in os.listdir(scan_path):
                    fpath = os.path.join(scan_path, fname)
                    if fpath in seen:
                        continue
                    seen.add(fpath)
                    if _is_executable(fpath):
                        executables.append((fpath, fname))
            except OSError:
                logger.debug('Cannot list directory: %s', scan_path)

    return executables


def _is_executable(path):
    """Check if path is a regular executable file."""
    try:
        st = os.stat(path)
        return (stat.S_ISREG(st.st_mode)
                and st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except OSError:
        return False


def _filter_non_rpm(candidates, logger):
    """Filter out binaries owned by RPM packages.

    Args:
        candidates: list of (path, name) tuples

    Returns:
        list of (path, name) tuples not owned by any RPM package
    """
    non_rpm = []

    for binary_path, binary_name in candidates:
        try:
            proc = subprocess.Popen(
                ['rpm', '-qf', binary_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = proc.communicate()
            output = stdout.decode('utf-8', errors='replace').strip()

            if proc.returncode != 0 or 'not owned' in output.lower():
                non_rpm.append((binary_path, binary_name))
        except OSError:
            # rpm not available, include everything
            non_rpm.append((binary_path, binary_name))

    return non_rpm
