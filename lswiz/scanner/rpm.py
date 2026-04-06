# -*- coding: utf-8 -*-
"""RPM package scanner.

Collects all packages installed via the RPM package manager.
"""
from __future__ import absolute_import
import subprocess


def scan_rpm_packages(logger):
    """Scan all installed RPM packages.

    Returns:
        list: list of package dicts with keys:
            - name (str)
            - version (str)
            - release (str)
            - arch (str)
            - source (str): always 'rpm'
            - status (str): set later by status classifier
            - cves (list): populated later by CVE matcher
    """
    logger.info('Scanning RPM packages...')

    try:
        proc = subprocess.Popen(
            ['rpm', '-qa', '--queryformat',
             '%{NAME}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\n'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = proc.communicate()
    except OSError:
        logger.error('rpm command not found. Is this a CentOS/RHEL system?')
        return []

    if proc.returncode != 0:
        logger.error('rpm -qa failed: %s', stderr.decode('utf-8', errors='replace'))
        return []

    packages = []
    for line in stdout.decode('utf-8', errors='replace').strip().split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) < 4:
            continue
        packages.append({
            'name': parts[0],
            'version': parts[1],
            'release': parts[2],
            'arch': parts[3],
            'source': 'rpm',
            'status': '',
            'cves': [],
        })

    return packages
