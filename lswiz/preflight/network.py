# -*- coding: utf-8 -*-
from __future__ import absolute_import
import subprocess
import sys


def check_connectivity(config, logger):
    """Check internet connectivity by DNS resolution and HTTP reach.

    Tests:
      1. DNS resolution (ping to known host)
      2. HTTP reach to Red Hat API and NVD API

    Exits with error if no connectivity.
    """
    logger.info('Checking internet connectivity...')

    # DNS check
    dns_ok = False
    try:
        result = subprocess.Popen(
            ['ping', '-c', '1', '-W', '3', '8.8.8.8'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result.wait()
        dns_ok = result.returncode == 0
    except OSError:
        pass

    if not dns_ok:
        logger.error('No internet connectivity (ping to 8.8.8.8 failed)')
        logger.error('lswiz requires internet access for CVE database queries')
        sys.exit(1)

    # HTTP reach to APIs
    import requests

    redhat_url = config['cve']['redhat']['base_url']
    nvd_url = config['cve']['nvd']['base_url']
    timeout = 10

    api_ok = True
    for name, url in [('Red Hat Security API', redhat_url), ('NVD API', nvd_url)]:
        try:
            resp = requests.head(url, timeout=timeout)
            if resp.status_code < 500:
                logger.info('  %s: reachable', name)
            else:
                logger.warning('  %s: returned %d', name, resp.status_code)
                api_ok = False
        except requests.RequestException as e:
            logger.warning('  %s: unreachable (%s)', name, str(e))
            api_ok = False

    if not api_ok:
        logger.warning('Some CVE APIs are unreachable. Results may be incomplete.')

    logger.info('Connectivity check complete')
