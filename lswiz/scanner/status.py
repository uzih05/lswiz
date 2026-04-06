# -*- coding: utf-8 -*-
"""Binary status classifier.

Classifies each package/binary into one of three states:
  RUNNING  — currently executing as a process
  INACTIVE — not running but referenced in system config
  UNUSED   — no evidence of active use
"""
from __future__ import absolute_import
import os
import subprocess
import re


def classify_status(packages, logger):
    """Classify the status of each package in-place.

    Args:
        packages: list of package dicts (mutated in-place)
        logger: logger instance
    """
    running_procs = _get_running_processes(logger)
    listening_ports = _get_listening_ports(logger)
    systemd_units = _get_systemd_units(logger)
    cron_refs = _get_cron_references(logger)
    etc_refs = _get_etc_references(logger)

    for pkg in packages:
        name = pkg['name']
        path = pkg.get('path', '')

        # check RUNNING
        if _is_running(name, path, running_procs):
            pkg['status'] = 'RUNNING'
            pkg['ports'] = _get_package_ports(name, path, listening_ports)
            continue

        # check INACTIVE (referenced somewhere)
        if _is_inactive(name, systemd_units, cron_refs, etc_refs):
            pkg['status'] = 'INACTIVE'
            continue

        # UNUSED
        pkg['status'] = 'UNUSED'


def _get_running_processes(logger):
    """Get set of running process names and their command lines.

    Returns:
        list of (pid, comm, cmdline) tuples
    """
    try:
        proc = subprocess.Popen(
            ['ps', 'axo', 'pid,comm,args'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, _ = proc.communicate()
        lines = stdout.decode('utf-8', errors='replace').strip().split('\n')
    except OSError:
        logger.debug('ps command failed')
        return []

    processes = []
    for line in lines[1:]:  # skip header
        parts = line.strip().split(None, 2)
        if len(parts) >= 2:
            pid = parts[0]
            comm = parts[1]
            cmdline = parts[2] if len(parts) > 2 else ''
            processes.append((pid, comm, cmdline))
    return processes


def _get_listening_ports(logger):
    """Get listening ports with their process info.

    Returns:
        list of (port, protocol, pid, process_name, bind_addr) tuples
    """
    ports = []

    # try ss first, then netstat
    for cmd in [['ss', '-tlnp'], ['netstat', '-tlnp']]:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, _ = proc.communicate()
            if proc.returncode == 0:
                output = stdout.decode('utf-8', errors='replace')
                ports = _parse_port_output(output, cmd[0])
                break
        except OSError:
            continue

    return ports


def _parse_port_output(output, tool):
    """Parse ss or netstat output into port tuples."""
    ports = []
    for line in output.strip().split('\n')[1:]:
        parts = line.split()
        if tool == 'ss' and len(parts) >= 5:
            local = parts[3]
            process_info = parts[-1] if len(parts) > 5 else ''
            addr, port = _split_addr_port(local)
            if port:
                ports.append((port, 'tcp', '', process_info, addr))
        elif tool == 'netstat' and len(parts) >= 7:
            local = parts[3]
            process_info = parts[6]
            addr, port = _split_addr_port(local)
            if port:
                pid_name = process_info.split('/')
                pid = pid_name[0] if pid_name else ''
                pname = pid_name[1] if len(pid_name) > 1 else ''
                ports.append((port, 'tcp', pid, pname, addr))
    return ports


def _split_addr_port(addr_str):
    """Split address:port or [::]:port into (address, port)."""
    if not addr_str:
        return ('', '')
    if ']:' in addr_str:
        # IPv6: [::]:port
        parts = addr_str.rsplit(':', 1)
        return (parts[0], parts[1])
    parts = addr_str.rsplit(':', 1)
    if len(parts) == 2:
        return (parts[0], parts[1])
    return (addr_str, '')


def _get_systemd_units(logger):
    """Get set of all systemd unit names."""
    try:
        proc = subprocess.Popen(
            ['systemctl', 'list-unit-files', '--type=service', '--no-pager', '--no-legend'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, _ = proc.communicate()
        units = set()
        for line in stdout.decode('utf-8', errors='replace').strip().split('\n'):
            parts = line.split()
            if parts:
                # "nginx.service enabled" → "nginx"
                unit_name = parts[0].replace('.service', '')
                units.add(unit_name)
        return units
    except OSError:
        return set()


def _get_cron_references(logger):
    """Get set of binary names referenced in crontabs."""
    refs = set()

    # user crontab
    try:
        proc = subprocess.Popen(
            ['crontab', '-l'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, _ = proc.communicate()
        if proc.returncode == 0:
            refs.update(_extract_binary_names(stdout.decode('utf-8', errors='replace')))
    except OSError:
        pass

    # system cron directories
    cron_dirs = ['/etc/crontab', '/etc/cron.d']
    for cron_path in cron_dirs:
        if os.path.isfile(cron_path):
            try:
                with open(cron_path, 'r') as f:
                    refs.update(_extract_binary_names(f.read()))
            except IOError:
                pass
        elif os.path.isdir(cron_path):
            try:
                for fname in os.listdir(cron_path):
                    fpath = os.path.join(cron_path, fname)
                    if os.path.isfile(fpath):
                        try:
                            with open(fpath, 'r') as f:
                                refs.update(_extract_binary_names(f.read()))
                        except IOError:
                            pass
            except OSError:
                pass

    return refs


def _get_etc_references(logger):
    """Get set of binary names referenced in /etc/ config files."""
    refs = set()
    try:
        proc = subprocess.Popen(
            ['find', '/etc', '-type', 'f', '-name', '*.conf',
             '-o', '-name', '*.cfg', '-o', '-name', '*.ini'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, _ = proc.communicate()
        config_files = stdout.decode('utf-8', errors='replace').strip().split('\n')

        for config_file in config_files:
            if not config_file or not os.path.isfile(config_file):
                continue
            try:
                with open(config_file, 'r') as f:
                    content = f.read(4096)  # read first 4KB only
                    refs.update(_extract_binary_names(content))
            except (IOError, UnicodeDecodeError):
                pass
    except OSError:
        pass

    return refs


def _extract_binary_names(text):
    """Extract potential binary names from text (paths or bare names)."""
    names = set()
    # match absolute paths to binaries
    for match in re.finditer(r'(/usr/local/[sb]?bin/|/opt/[\w.-]+/bin/)([\w.-]+)', text):
        names.add(match.group(2))
    # match common binary references
    for match in re.finditer(r'\b(nginx|httpd|apache2|mysql|mysqld|postgres|redis-server|node|java|php|openssl)\b', text):
        names.add(match.group(1))
    return names


def _is_running(name, path, processes):
    """Check if binary is currently running."""
    for pid, comm, cmdline in processes:
        if comm == name:
            return True
        if path and path in cmdline:
            return True
    return False


def _is_inactive(name, systemd_units, cron_refs, etc_refs):
    """Check if binary is referenced but not running."""
    if name in systemd_units:
        return True
    if name in cron_refs:
        return True
    if name in etc_refs:
        return True
    return False


def _get_package_ports(name, path, listening_ports):
    """Get list of ports this package is listening on.

    Returns:
        list of dicts with 'port', 'protocol', 'bind_addr'
    """
    ports = []
    for port, protocol, pid, process_info, bind_addr in listening_ports:
        if name in process_info or (path and path in process_info):
            is_external = bind_addr in ('0.0.0.0', '*', '[::]', '::')
            ports.append({
                'port': port,
                'protocol': protocol,
                'bind_addr': bind_addr,
                'external': is_external,
            })
    return ports
