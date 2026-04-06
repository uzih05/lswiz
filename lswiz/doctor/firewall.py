# -*- coding: utf-8 -*-
"""Firewall mitigation recommendations."""
from __future__ import absolute_import


def recommend_firewall_rules(pkg, logger):
    """Generate firewall rule recommendations for a running package.

    Args:
        pkg: package dict with 'ports' info
        logger: logger instance

    Returns:
        list of recommendation dicts
    """
    recommendations = []
    ports = pkg.get('ports', [])

    for port_info in ports:
        if not port_info.get('external', False):
            continue

        port = port_info['port']
        protocol = port_info.get('protocol', 'tcp')

        # recommend restricting to specific IPs or blocking
        recommendations.append({
            'type': 'firewall_restrict',
            'priority': 'high',
            'description': 'Restrict external access to port {port}/{proto} ({name})'.format(
                port=port, proto=protocol, name=pkg['name'],
            ),
            'commands': [
                '# Option 1: Block port entirely',
                'firewall-cmd --permanent --remove-port={port}/{proto}'.format(
                    port=port, proto=protocol,
                ),
                'firewall-cmd --reload',
                '',
                '# Option 2: Allow only specific IPs (replace IP)',
                'firewall-cmd --permanent --add-rich-rule=\'rule family="ipv4" '
                'source address="TRUSTED_IP/32" port port="{port}" '
                'protocol="{proto}" accept\''.format(
                    port=port, proto=protocol,
                ),
                'firewall-cmd --permanent --remove-port={port}/{proto}'.format(
                    port=port, proto=protocol,
                ),
                'firewall-cmd --reload',
            ],
        })

    # if running but no external ports, suggest binding to localhost
    if not any(p.get('external', False) for p in ports) and ports:
        recommendations.append({
            'type': 'firewall_info',
            'priority': 'low',
            'description': '{name} is bound to localhost only (good)'.format(
                name=pkg['name'],
            ),
            'commands': [],
        })

    return recommendations
