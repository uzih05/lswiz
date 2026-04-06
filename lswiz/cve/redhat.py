# -*- coding: utf-8 -*-
"""Red Hat Security API client for RPM package CVE matching."""
from __future__ import absolute_import
import time
import requests


def match_rpm_cves(packages, config, logger):
    """Match RPM packages against Red Hat Security API.

    Queries the Red Hat Security Data API for each unique package name
    and attaches matching CVEs to the package dicts.

    Args:
        packages: list of RPM package dicts (mutated in-place)
        config: lswiz config dict
        logger: logger instance
    """
    api_config = config['cve']['redhat']
    base_url = api_config['base_url']
    timeout = api_config.get('timeout', 30)
    eol_date = config.get('eol_date', '2024-06-30')

    # group packages by name to avoid duplicate queries
    by_name = {}
    for pkg in packages:
        if pkg['source'] != 'rpm':
            continue
        name = pkg['name']
        if name not in by_name:
            by_name[name] = []
        by_name[name].append(pkg)

    total = len(by_name)
    logger.info('Querying Red Hat Security API for %d unique packages...', total)

    for idx, (name, pkgs) in enumerate(by_name.items()):
        if (idx + 1) % 50 == 0:
            logger.info('  Progress: %d/%d packages queried', idx + 1, total)

        cves = _query_package_cves(name, base_url, timeout, eol_date, logger)

        # attach CVEs to all packages with this name
        for pkg in pkgs:
            version = pkg['version']
            matched = _filter_by_version(cves, name, version, eol_date)
            pkg['cves'] = matched

        # rate limiting: be gentle with the API
        time.sleep(0.2)

    matched_count = sum(len(p['cves']) for p in packages if p['source'] == 'rpm')
    logger.info('Red Hat API: %d CVEs matched across %d packages', matched_count, total)


def _query_package_cves(package_name, base_url, timeout, eol_date, logger):
    """Query Red Hat Security API for CVEs affecting a package.

    Args:
        package_name: RPM package name
        base_url: API base URL
        timeout: request timeout
        eol_date: EOL date string for filtering

    Returns:
        list of CVE dicts
    """
    url = '{base}/cve.json'.format(base=base_url)
    params = {
        'package': package_name,
    }

    try:
        resp = requests.get(url, params=params, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                return data
        elif resp.status_code == 404:
            return []
        else:
            logger.debug('Red Hat API returned %d for %s', resp.status_code, package_name)
    except requests.RequestException as e:
        logger.debug('Red Hat API error for %s: %s', package_name, str(e))

    return []


def _filter_by_version(cves, package_name, package_version, eol_date=''):
    """Filter CVEs relevant to the specific package version.

    Args:
        cves: list of CVE dicts from Red Hat API
        package_name: package name
        package_version: installed version
        eol_date: only include CVEs published after this date (YYYY-MM-DD)

    Returns:
        list of filtered CVE dicts with normalized fields
    """
    results = []
    for cve in cves:
        cve_id = cve.get('CVE', '')
        severity = cve.get('severity', 'unknown')
        public_date = cve.get('public_date', '')
        # filter by EOL date
        if eol_date and public_date and public_date < eol_date:
            continue

        cvss3_vector = cve.get('cvss3_scoring_vector', '')
        cvss3_base = 0.0
        resource_url = cve.get('resource_url', '')

        # extract CVSS3 base score
        score_str = cve.get('cvss3_score', '')
        if score_str:
            try:
                cvss3_base = float(score_str)
            except (ValueError, TypeError):
                pass

        results.append({
            'cve_id': cve_id,
            'severity': severity,
            'public_date': public_date,
            'cvss3_score': cvss3_base,
            'cvss3_vector': cvss3_vector,
            'description': cve.get('bugzilla_description', ''),
            'resource_url': resource_url or 'https://access.redhat.com/security/cve/{}'.format(cve_id),
            'source': 'redhat',
        })

    return results
