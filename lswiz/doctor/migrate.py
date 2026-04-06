# -*- coding: utf-8 -*-
"""Migration urgency assessment."""
from __future__ import absolute_import


def assess_migration_urgency(scored_results, logger):
    """Assess OS migration urgency based on overall risk.

    Args:
        scored_results: dict from scoring engine
        logger: logger instance

    Returns:
        dict with 'level', 'score', 'reason'
    """
    server_grade = scored_results.get('server_grade', 'none')
    max_score = scored_results.get('server_max_score', 0.0)
    total_cves = scored_results.get('total_cves', 0)
    severity = scored_results.get('severity_counts', {})

    critical_count = severity.get('critical', 0)
    high_count = severity.get('high', 0)

    # determine urgency level
    if critical_count > 0 or max_score >= 9.0:
        level = 'IMMEDIATE'
        reason = (
            'Critical vulnerabilities detected ({n} critical CVEs). '
            'System is at severe risk. Migrate to a supported OS immediately.'
        ).format(n=critical_count)
    elif high_count >= 5 or max_score >= 7.0:
        level = 'URGENT'
        reason = (
            'Multiple high-severity vulnerabilities ({n} high CVEs). '
            'Plan migration within 30 days.'
        ).format(n=high_count)
    elif total_cves >= 10 or max_score >= 4.0:
        level = 'PLANNED'
        reason = (
            '{n} CVEs detected with moderate risk. '
            'Schedule migration within 90 days.'
        ).format(n=total_cves)
    elif total_cves > 0:
        level = 'ADVISORY'
        reason = (
            '{n} low-risk CVEs detected. '
            'Migration recommended but not urgent. Monitor for escalation.'
        ).format(n=total_cves)
    else:
        level = 'MONITOR'
        reason = (
            'No CVEs detected post-EOL. Continue monitoring. '
            'Migration still recommended as no future patches will be provided.'
        )

    logger.info('Migration urgency: %s', level)
    logger.info('  %s', reason)

    return {
        'level': level,
        'score': max_score,
        'total_cves': total_cves,
        'critical_count': critical_count,
        'high_count': high_count,
        'reason': reason,
    }
