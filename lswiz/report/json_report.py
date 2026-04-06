# -*- coding: utf-8 -*-
"""JSON report generator."""
from __future__ import absolute_import
import json
import os
import sys
from datetime import datetime


def generate_json_report(results, config, logger):
    """Generate JSON report.

    Outputs to stdout and optionally saves to file.
    """
    report = {
        'generated_at': datetime.now().isoformat(),
        'tool': 'lswiz',
        'server_grade': results.get('server_grade', 'none'),
        'server_max_score': results.get('server_max_score', 0.0),
        'total_cves': results.get('total_cves', 0),
        'severity_counts': results.get('severity_counts', {}),
        'migration_urgency': results.get('migration_urgency', {}),
        'packages': _serialize_packages(results.get('packages', [])),
        'unused_clean': results.get('unused_clean', []),
    }

    json_str = json.dumps(report, indent=2, ensure_ascii=False)

    # output to stdout
    sys.stdout.write(json_str + '\n')

    # optionally save to file
    output_dir = config.get('report', {}).get('output_dir', '')
    if output_dir and os.path.isdir(output_dir):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = 'lswiz_report_{}.json'.format(timestamp)
        filepath = os.path.join(output_dir, filename)
        try:
            with open(filepath, 'w') as f:
                f.write(json_str)
            logger.info('JSON report saved: %s', filepath)
        except IOError as e:
            logger.warning('Could not save report: %s', str(e))


def _serialize_packages(packages):
    """Serialize packages for JSON output, keeping only relevant fields."""
    serialized = []
    for pkg in packages:
        if not pkg.get('cves') and pkg.get('status') != 'UNUSED':
            continue

        entry = {
            'name': pkg.get('name', ''),
            'version': pkg.get('version', ''),
            'source': pkg.get('source', ''),
            'status': pkg.get('status', ''),
            'risk_score': pkg.get('risk_score', 0.0),
            'risk_grade': pkg.get('risk_grade', 'none'),
        }

        if pkg.get('path'):
            entry['path'] = pkg['path']
        if pkg.get('detection'):
            entry['detection'] = pkg['detection']
        if pkg.get('cpe'):
            entry['cpe'] = pkg['cpe']
        if pkg.get('cves'):
            entry['cves'] = pkg['cves']
        if pkg.get('recommendations'):
            entry['recommendations'] = pkg['recommendations']
        if pkg.get('ports'):
            entry['ports'] = pkg['ports']

        serialized.append(entry)

    return serialized
