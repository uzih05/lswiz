# -*- coding: utf-8 -*-
from __future__ import absolute_import
import os
import re
import subprocess
import glob as globmod


VAULT_BASEURL = 'http://vault.centos.org/7.9.2009'
REPO_DIR = '/etc/yum.repos.d'


def check_and_fix_repos(config, logger):
    """Check YUM repository status and fix if broken due to EOL.

    For CentOS 7 EOL systems:
      - Replaces dead mirror URLs with vault.centos.org
      - Ensures at least base repo is functional
      - Optionally adds EPEL if missing
    """
    logger.info('Checking YUM repository status...')

    if not os.path.isdir(REPO_DIR):
        logger.warning('YUM repo directory not found: %s', REPO_DIR)
        return

    # test if yum works at all
    yum_ok = _test_yum(logger)
    if yum_ok:
        logger.info('YUM repositories are functional')
        return

    logger.warning('YUM repositories are broken. Attempting to fix...')

    # find and fix CentOS repo files
    repo_files = globmod.glob(os.path.join(REPO_DIR, 'CentOS-*.repo'))
    fixed = 0
    for repo_file in repo_files:
        if _fix_repo_file(repo_file, logger):
            fixed += 1

    if fixed > 0:
        logger.info('Fixed %d repo files. Cleaning YUM cache...', fixed)
        proc = subprocess.Popen(['yum', 'clean', 'all'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate()

    # verify fix worked
    if _test_yum(logger):
        logger.info('YUM repositories restored successfully')
    else:
        logger.warning('YUM repositories still broken after fix attempt')
        logger.warning('Manual intervention may be required')


def _test_yum(logger):
    """Test if yum repolist works."""
    try:
        result = subprocess.Popen(
            ['yum', 'repolist', '-q'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = result.communicate()
        return result.returncode == 0
    except OSError:
        logger.debug('yum command not found')
        return False


def _fix_repo_file(repo_file, logger):
    """Replace dead mirror URLs with vault.centos.org in a repo file.

    Returns:
        bool: True if file was modified
    """
    try:
        with open(repo_file, 'r') as f:
            content = f.read()
    except IOError:
        return False

    original = content

    # comment out mirrorlist lines
    content = re.sub(
        r'^(mirrorlist=.*)$',
        r'#\1',
        content,
        flags=re.MULTILINE,
    )

    # uncomment and fix baseurl lines
    content = re.sub(
        r'^#?\s*baseurl=http://mirror\.centos\.org/centos/\$releasever/(.+)$',
        r'baseurl={}/\1'.format(VAULT_BASEURL),
        content,
        flags=re.MULTILINE,
    )

    if content != original:
        # backup original
        backup = repo_file + '.bak.lswiz'
        if not os.path.exists(backup):
            try:
                with open(backup, 'w') as f:
                    f.write(original)
            except IOError:
                pass

        try:
            with open(repo_file, 'w') as f:
                f.write(content)
            logger.info('  Fixed: %s', repo_file)
            return True
        except IOError as e:
            logger.error('  Failed to write %s: %s', repo_file, str(e))

    return False
