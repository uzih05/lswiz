# -*- coding: utf-8 -*-
from __future__ import absolute_import
import os
import yaml

DEFAULT_CONFIG_PATHS = [
    '/etc/lswiz/config.yaml',
    os.path.expanduser('~/.lswiz/config.yaml'),
    './config/config.yaml',
]

DEFAULT_CONFIG = {
    'scan': {
        'rpm': True,
        'manual': True,
        'manual_paths': [
            '/usr/local/bin',
            '/usr/local/sbin',
            '/opt',
            '/usr/bin',
            '/usr/sbin',
        ],
    },
    'cve': {
        'redhat': {
            'base_url': 'https://access.redhat.com/hydra/rest/securitydata',
            'timeout': 30,
        },
        'nvd': {
            'base_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'api_key': '',
            'timeout': 30,
        },
    },
    'eol_date': '2024-06-30',
    'scoring': {
        'status_weight': {
            'running_exposed': 1.5,
            'running_local': 1.2,
            'inactive': 0.8,
            'unused': 0.3,
        },
        'network_weight': {
            'external': 1.5,
            'localhost': 0.8,
            'no_port': 0.6,
        },
    },
    'report': {
        'format': 'text',
        'output_dir': '/tmp/lswiz-reports',
    },
    'log': {
        'level': 'INFO',
        'file': '/var/log/lswiz/lswiz.log',
    },
}


def _deep_merge(base, override):
    """Merge override dict into base dict recursively."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path=None):
    """Load config from YAML file, falling back to defaults.

    Args:
        config_path: explicit path to config file. If None, searches
                     DEFAULT_CONFIG_PATHS in order.

    Returns:
        dict: merged configuration
    """
    if config_path and os.path.isfile(config_path):
        with open(config_path, 'r') as f:
            user_config = yaml.safe_load(f) or {}
        return _deep_merge(DEFAULT_CONFIG, user_config)

    for path in DEFAULT_CONFIG_PATHS:
        if os.path.isfile(path):
            with open(path, 'r') as f:
                user_config = yaml.safe_load(f) or {}
            return _deep_merge(DEFAULT_CONFIG, user_config)

    return DEFAULT_CONFIG.copy()
