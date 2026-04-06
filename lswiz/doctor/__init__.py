# -*- coding: utf-8 -*-
"""Doctor module — mitigation strategy recommendation engine."""
from __future__ import absolute_import

from lswiz.doctor.firewall import recommend_firewall_rules
from lswiz.doctor.service import recommend_service_actions
from lswiz.doctor.migrate import assess_migration_urgency


def recommend_mitigations(scored_results, config, logger):
    """Generate mitigation recommendations for all packages.

    Args:
        scored_results: dict from risk scoring engine
        config: lswiz config dict
        logger: logger instance

    Returns:
        dict: scored_results with added 'recommendations' per package
              and 'migration_urgency' at top level
    """
    packages = scored_results['packages']
    unused_no_cve = []

    for pkg in packages:
        cves = pkg.get('cves', [])
        status = pkg.get('status', 'UNUSED')
        recommendations = []

        if not cves and status == 'UNUSED':
            unused_no_cve.append(pkg['name'])
            continue

        if not cves:
            continue

        # UNUSED + CVE → recommend removal
        if status == 'UNUSED':
            recommendations.append({
                'type': 'remove',
                'priority': 'high',
                'description': 'Remove unused binary with known vulnerabilities',
                'command': 'rm {}'.format(pkg.get('path', pkg['name'])),
            })

        # RUNNING → firewall and/or service actions
        if status == 'RUNNING':
            fw_rules = recommend_firewall_rules(pkg, logger)
            recommendations.extend(fw_rules)

        # RUNNING or INACTIVE → service actions
        if status in ('RUNNING', 'INACTIVE'):
            svc_actions = recommend_service_actions(pkg, logger)
            recommendations.extend(svc_actions)

        pkg['recommendations'] = recommendations

    # display unused binaries without CVEs (info only)
    scored_results['unused_clean'] = unused_no_cve

    # migration urgency assessment
    urgency = assess_migration_urgency(scored_results, logger)
    scored_results['migration_urgency'] = urgency

    # summary
    rec_count = sum(len(p.get('recommendations', [])) for p in packages)
    logger.info('Generated %d recommendations', rec_count)
    if unused_no_cve:
        logger.info('Found %d unused binaries with no CVEs (info only)', len(unused_no_cve))
    logger.info('Migration urgency: %s', urgency['level'])

    return scored_results
