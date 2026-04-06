# -*- coding: utf-8 -*-
"""Service-level mitigation recommendations."""
from __future__ import absolute_import


def recommend_service_actions(pkg, logger):
    """Generate service-level recommendations.

    Args:
        pkg: package dict
        logger: logger instance

    Returns:
        list of recommendation dicts
    """
    recommendations = []
    status = pkg.get('status', '')
    name = pkg['name']
    risk_grade = pkg.get('risk_grade', 'none')

    if status == 'INACTIVE':
        if risk_grade in ('critical', 'high'):
            recommendations.append({
                'type': 'service_disable',
                'priority': 'high',
                'description': 'Disable inactive service with critical/high vulnerabilities',
                'commands': [
                    'systemctl disable {name}'.format(name=name),
                    '# Also consider removing if not needed:',
                    '# yum remove {name} (if RPM)'.format(name=name),
                ],
            })
        else:
            recommendations.append({
                'type': 'service_review',
                'priority': 'medium',
                'description': 'Review if inactive service is still needed',
                'commands': [
                    'systemctl status {name}'.format(name=name),
                    'systemctl disable {name}  # if not needed'.format(name=name),
                ],
            })

    if status == 'RUNNING':
        if risk_grade in ('critical', 'high'):
            recommendations.append({
                'type': 'service_config',
                'priority': 'high',
                'description': 'Harden {name} configuration to reduce attack surface'.format(
                    name=name,
                ),
                'commands': _get_hardening_commands(name),
            })

        # always recommend version check for running services
        recommendations.append({
            'type': 'service_update',
            'priority': 'medium',
            'description': 'Check for available updates or consider alternative',
            'commands': [
                '# Check current version',
                '{name} --version 2>/dev/null || {name} -v 2>/dev/null'.format(name=name),
                '# Check if newer version is available from third-party repo',
            ],
        })

    return recommendations


def _get_hardening_commands(name):
    """Get service-specific hardening suggestions."""
    hardening = {
        'nginx': [
            '# /etc/nginx/nginx.conf',
            'server_tokens off;          # hide version',
            'ssl_protocols TLSv1.2 TLSv1.3;  # disable old TLS',
            'add_header X-Content-Type-Options nosniff;',
        ],
        'httpd': [
            '# /etc/httpd/conf/httpd.conf',
            'ServerTokens Prod           # hide version',
            'ServerSignature Off',
            'TraceEnable Off',
        ],
        'redis-server': [
            '# /etc/redis.conf',
            'bind 127.0.0.1             # bind to localhost only',
            'requirepass YOUR_PASSWORD   # set auth password',
            'rename-command FLUSHALL ""  # disable dangerous commands',
        ],
        'mysqld': [
            '# /etc/my.cnf',
            'bind-address = 127.0.0.1   # bind to localhost only',
            'local-infile = 0           # disable LOAD DATA LOCAL',
        ],
        'postgres': [
            '# /var/lib/pgsql/data/pg_hba.conf',
            '# Restrict connections to localhost',
            '# /var/lib/pgsql/data/postgresql.conf',
            "listen_addresses = 'localhost'",
        ],
    }

    commands = hardening.get(name, [])
    if not commands:
        commands = [
            '# Review configuration files for {}'.format(name),
            '# Disable unnecessary features and restrict access',
        ]
    return commands
