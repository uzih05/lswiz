# -*- coding: utf-8 -*-
"""NVD API 2.0 client for manual binary CVE matching via CPE."""
from __future__ import absolute_import
import time
import requests


# rate limit: 5 requests per 30 seconds without API key
# with API key: 50 requests per 30 seconds
RATE_LIMIT_NO_KEY = 6.0   # seconds between requests
RATE_LIMIT_WITH_KEY = 0.6


def match_manual_cves(binaries, config, logger):
    """Match manually installed binaries against NVD API via CPE.

    Only queries binaries with CONFIRMED detection (have valid CPE).

    Args:
        binaries: list of manual binary dicts (mutated in-place)
        config: lswiz config dict
        logger: logger instance
    """
    api_config = config['cve']['nvd']
    base_url = api_config['base_url']
    api_key = api_config.get('api_key', '')
    timeout = api_config.get('timeout', 30)
    eol_date = config.get('eol_date', '2024-06-30')

    rate_limit = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_NO_KEY

    confirmed = [b for b in binaries if b.get('detection') == 'CONFIRMED' and b.get('cpe')]
    if not confirmed:
        logger.info('No CONFIRMED binaries with CPE to query NVD')
        return

    logger.info('Querying NVD API for %d CONFIRMED binaries...', len(confirmed))
    if not api_key:
        logger.warning('No NVD API key configured. Rate limited to 5 req/30s.')
        logger.warning('Set cve.nvd.api_key in config for faster queries.')

    for idx, binary in enumerate(confirmed):
        cpe = binary['cpe']
        name = binary['name']

        logger.info('  [%d/%d] Querying %s (%s)', idx + 1, len(confirmed), name, cpe)
        cves = _query_cpe_cves(cpe, base_url, api_key, timeout, eol_date, logger)
        binary['cves'] = cves

        if cves:
            logger.info('    Found %d CVEs', len(cves))

        # respect rate limit
        if idx < len(confirmed) - 1:
            time.sleep(rate_limit)

    total_cves = sum(len(b['cves']) for b in confirmed)
    logger.info('NVD API: %d CVEs matched across %d binaries', total_cves, len(confirmed))


def _query_cpe_cves(cpe_name, base_url, api_key, timeout, eol_date, logger):
    """Query NVD API 2.0 for CVEs matching a CPE.

    Args:
        cpe_name: CPE 2.3 formatted string
        base_url: NVD API base URL
        api_key: API key (empty string if none)
        timeout: request timeout
        eol_date: filter CVEs published after this date

    Returns:
        list of CVE dicts
    """
    params = {
        'cpeName': cpe_name,
        'pubStartDate': '{}T00:00:00.000'.format(eol_date),
        'pubEndDate': '2099-12-31T23:59:59.999',
    }

    headers = {}
    if api_key:
        headers['apiKey'] = api_key

    try:
        resp = requests.get(base_url, params=params, headers=headers, timeout=timeout)

        if resp.status_code == 200:
            data = resp.json()
            return _parse_nvd_response(data)
        elif resp.status_code == 403:
            logger.warning('NVD API rate limit exceeded. Waiting...')
            time.sleep(30)
            return []
        else:
            logger.debug('NVD API returned %d for %s', resp.status_code, cpe_name)
    except requests.RequestException as e:
        logger.debug('NVD API error for %s: %s', cpe_name, str(e))

    return []


def _parse_nvd_response(data):
    """Parse NVD API 2.0 response into CVE dicts.

    Args:
        data: parsed JSON response

    Returns:
        list of CVE dicts with normalized fields
    """
    results = []
    vulnerabilities = data.get('vulnerabilities', [])

    for vuln in vulnerabilities:
        cve_data = vuln.get('cve', {})
        cve_id = cve_data.get('id', '')

        # extract CVSS score
        cvss3_score = 0.0
        cvss3_vector = ''
        metrics = cve_data.get('metrics', {})

        # try cvssMetricV31 first, then V30
        for metric_key in ['cvssMetricV31', 'cvssMetricV30']:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get('cvssData', {})
                cvss3_score = cvss_data.get('baseScore', 0.0)
                cvss3_vector = cvss_data.get('vectorString', '')
                break

        # extract description (English)
        description = ''
        for desc in cve_data.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        # published date
        published = cve_data.get('published', '')

        results.append({
            'cve_id': cve_id,
            'severity': _score_to_severity(cvss3_score),
            'public_date': published,
            'cvss3_score': cvss3_score,
            'cvss3_vector': cvss3_vector,
            'description': description,
            'resource_url': 'https://nvd.nist.gov/vuln/detail/{}'.format(cve_id),
            'source': 'nvd',
        })

    return results


def _score_to_severity(score):
    """Convert CVSS score to severity string."""
    if score >= 9.0:
        return 'critical'
    elif score >= 7.0:
        return 'important'
    elif score >= 4.0:
        return 'moderate'
    elif score > 0:
        return 'low'
    return 'unknown'
