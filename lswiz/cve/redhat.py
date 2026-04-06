# -*- coding: utf-8 -*-
"""Red Hat Security API client for RPM package CVE matching.

Uses batch queries (comma-separated package names + 'after' date filter)
to minimize API calls.
"""
from __future__ import absolute_import
import time
import requests

BATCH_SIZE = 10  # packages per API call


def match_rpm_cves(packages, config, logger):
    """Match RPM packages against Red Hat Security API.

    Uses batch queries: groups packages into chunks of BATCH_SIZE and
    queries them in a single API call with comma-separated names.

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

    names = list(by_name.keys())
    total = len(names)
    batches = [names[i:i + BATCH_SIZE] for i in range(0, total, BATCH_SIZE)]

    logger.info(
        'Querying Red Hat Security API for %d packages in %d batches...',
        total, len(batches),
    )

    all_cves = {}  # package_name -> list of CVE dicts
    for batch_idx, batch in enumerate(batches):
        if (batch_idx + 1) % 5 == 0 or batch_idx == len(batches) - 1:
            logger.info(
                '  Batch %d/%d (%d packages queried)',
                batch_idx + 1, len(batches), min((batch_idx + 1) * BATCH_SIZE, total),
            )

        cves = _query_batch_cves(batch, base_url, timeout, eol_date, logger)

        # index CVEs by affected package name
        for cve in cves:
            affected = cve.get('affected_packages', [])
            cve_assigned = False
            for pkg_name in batch:
                # check if this CVE mentions this package
                if _cve_affects_package(cve, pkg_name, affected):
                    if pkg_name not in all_cves:
                        all_cves[pkg_name] = []
                    all_cves[pkg_name].append(cve)
                    cve_assigned = True

            # if no specific match via affected_packages, try description match
            if not cve_assigned:
                desc = cve.get('bugzilla_description', '').lower()
                for pkg_name in batch:
                    if desc.startswith(pkg_name.lower() + ':'):
                        if pkg_name not in all_cves:
                            all_cves[pkg_name] = []
                        all_cves[pkg_name].append(cve)

        # rate limiting
        time.sleep(0.3)

    # attach CVEs to packages
    for name, pkgs in by_name.items():
        cves = all_cves.get(name, [])
        for pkg in pkgs:
            pkg['cves'] = _normalize_cves(cves)

    matched_count = sum(len(p['cves']) for p in packages if p['source'] == 'rpm')
    logger.info('Red Hat API: %d CVEs matched across %d packages', matched_count, total)


def _query_batch_cves(package_names, base_url, timeout, eol_date, logger):
    """Query Red Hat Security API for CVEs affecting a batch of packages.

    Args:
        package_names: list of RPM package names
        base_url: API base URL
        timeout: request timeout
        eol_date: EOL date for 'after' filter

    Returns:
        list of CVE dicts
    """
    url = '{base}/cve.json'.format(base=base_url)
    params = {
        'package': ','.join(package_names),
        'after': eol_date,
    }

    all_cves = []
    page = 1

    while True:
        params['page'] = page
        params['per_page'] = 100

        try:
            resp = requests.get(url, params=params, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and data:
                    all_cves.extend(data)
                    if len(data) < 100:
                        break  # last page
                    page += 1
                else:
                    break
            elif resp.status_code == 404:
                break
            else:
                logger.debug(
                    'Red Hat API returned %d for batch %s',
                    resp.status_code, ','.join(package_names),
                )
                break
        except requests.RequestException as e:
            logger.debug('Red Hat API error for batch: %s', str(e))
            break

    return all_cves


def _cve_affects_package(cve, package_name, affected_packages):
    """Check if a CVE affects a specific package.

    Matching priority:
      1. affected_packages list contains package name
      2. bugzilla_description starts with "package_name:" prefix

    Args:
        cve: CVE dict from API
        package_name: package name to check
        affected_packages: list of affected package strings from CVE

    Returns:
        bool
    """
    # check affected_packages list (format: "openssl-1.0.2k-26.el7_9" or container hashes)
    for affected in affected_packages:
        # split on "/" for container image paths, take last segment
        segment = affected.rsplit('/', 1)[-1] if '/' in affected else affected
        # strip hash suffix for container images
        if ':sha256:' in segment:
            segment = segment.split(':sha256:')[0]
        if segment.startswith(package_name + '-') or segment == package_name:
            return True

    # check bugzilla description prefix pattern: "package_name: description"
    desc = cve.get('bugzilla_description', '')
    if desc.lower().startswith(package_name.lower() + ':'):
        return True

    return False


def _normalize_cves(cves):
    """Normalize CVE dicts to standard format.

    Args:
        cves: list of raw CVE dicts from Red Hat API

    Returns:
        list of normalized CVE dicts
    """
    results = []
    seen = set()

    for cve in cves:
        cve_id = cve.get('CVE', '')
        if cve_id in seen:
            continue
        seen.add(cve_id)

        cvss3_vector = cve.get('cvss3_scoring_vector', '')
        cvss3_base = 0.0

        score_str = cve.get('cvss3_score', '')
        if score_str:
            try:
                cvss3_base = float(score_str)
            except (ValueError, TypeError):
                pass

        results.append({
            'cve_id': cve_id,
            'severity': cve.get('severity', 'unknown'),
            'public_date': cve.get('public_date', ''),
            'cvss3_score': cvss3_base,
            'cvss3_vector': cvss3_vector,
            'description': cve.get('bugzilla_description', ''),
            'resource_url': cve.get('resource_url', '') or 'https://access.redhat.com/security/cve/{}'.format(cve_id),
            'source': 'redhat',
        })

    return results
