# -*- coding: utf-8 -*-
"""Context-based risk scoring engine.

Calculates risk scores by combining CVSS base scores with operational
context: binary status (RUNNING/INACTIVE/UNUSED) and network exposure.
"""
from __future__ import absolute_import


def calculate_risk_scores(packages, config, logger):
    """Calculate contextual risk scores for all packages.

    Formula:
        contextual_score = cvss_base * status_weight * network_weight

    Mutates packages in-place and returns a summary dict.

    Args:
        packages: list of package dicts with 'cves', 'status', 'ports'
        config: lswiz config dict
        logger: logger instance

    Returns:
        dict with:
            - packages: the scored package list
            - server_grade: overall server risk grade
            - summary: counts by severity
    """
    weights = config.get('scoring', {})
    status_weights = weights.get('status_weight', {})
    network_weights = weights.get('network_weight', {})

    max_score = 0.0
    total_cves = 0
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0}

    for pkg in packages:
        cves = pkg.get('cves', [])
        if not cves:
            pkg['risk_score'] = 0.0
            pkg['risk_grade'] = 'none'
            continue

        status = pkg.get('status', 'UNUSED')
        ports = pkg.get('ports', [])

        s_weight = _get_status_weight(status, ports, status_weights)
        n_weight = _get_network_weight(ports, network_weights)

        pkg_max_score = 0.0
        for cve in cves:
            cvss = cve.get('cvss3_score', 0.0)
            contextual = cvss * s_weight * n_weight
            # cap at 10.0
            contextual = min(contextual, 10.0)
            cve['contextual_score'] = round(contextual, 2)

            if contextual > pkg_max_score:
                pkg_max_score = contextual

            grade = _score_to_grade(contextual)
            cve['risk_grade'] = grade
            severity_counts[grade] = severity_counts.get(grade, 0) + 1
            total_cves += 1

        pkg['risk_score'] = round(pkg_max_score, 2)
        pkg['risk_grade'] = _score_to_grade(pkg_max_score)
        pkg['status_weight'] = s_weight
        pkg['network_weight'] = n_weight

        if pkg_max_score > max_score:
            max_score = pkg_max_score

        logger.debug(
            '%s: score=%.2f (status=%s w=%.1f, net w=%.1f, cves=%d)',
            pkg['name'], pkg_max_score, status, s_weight, n_weight, len(cves),
        )

    server_grade = _score_to_grade(max_score)
    logger.info('Server risk grade: %s (max score: %.2f)', server_grade.upper(), max_score)
    logger.info(
        'CVE breakdown: critical=%d, high=%d, medium=%d, low=%d',
        severity_counts.get('critical', 0),
        severity_counts.get('high', 0),
        severity_counts.get('medium', 0),
        severity_counts.get('low', 0),
    )

    return {
        'packages': packages,
        'server_grade': server_grade,
        'server_max_score': round(max_score, 2),
        'total_cves': total_cves,
        'severity_counts': severity_counts,
    }


def _get_status_weight(status, ports, weights):
    """Get status weight based on binary status and port exposure."""
    if status == 'RUNNING':
        has_external = any(p.get('external', False) for p in ports)
        if has_external:
            return weights.get('running_exposed', 1.5)
        return weights.get('running_local', 1.2)
    elif status == 'INACTIVE':
        return weights.get('inactive', 0.8)
    else:  # UNUSED
        return weights.get('unused', 0.3)


def _get_network_weight(ports, weights):
    """Get network weight based on port exposure."""
    if not ports:
        return weights.get('no_port', 0.6)

    has_external = any(p.get('external', False) for p in ports)
    if has_external:
        return weights.get('external', 1.5)
    return weights.get('localhost', 0.8)


def _score_to_grade(score):
    """Convert risk score to grade string."""
    if score >= 9.0:
        return 'critical'
    elif score >= 7.0:
        return 'high'
    elif score >= 4.0:
        return 'medium'
    elif score > 0:
        return 'low'
    return 'none'
