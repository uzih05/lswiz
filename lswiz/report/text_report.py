# -*- coding: utf-8 -*-
"""Text report generator for terminal output."""
from __future__ import absolute_import
import sys


# ANSI color codes
COLORS = {
    'critical': '\033[91m',  # red
    'high': '\033[93m',      # yellow
    'medium': '\033[33m',    # dark yellow
    'low': '\033[36m',       # cyan
    'none': '\033[32m',      # green
    'reset': '\033[0m',
    'bold': '\033[1m',
    'dim': '\033[2m',
}


def generate_text_report(results, config, logger):
    """Print formatted text report to stdout."""
    out = sys.stdout
    use_color = hasattr(out, 'isatty') and out.isatty()

    _print_header(out, results, use_color)
    _print_vulnerable_packages(out, results, use_color)
    _print_recommendations(out, results, use_color)
    _print_unused_clean(out, results, use_color)
    _print_migration(out, results, use_color)
    _print_footer(out, results, use_color)


def _c(color_name, text, use_color):
    """Apply color to text if terminal supports it."""
    if use_color:
        return '{}{}{}'.format(COLORS.get(color_name, ''), text, COLORS['reset'])
    return text


def _print_header(out, results, use_color):
    out.write('\n')
    out.write(_c('bold', '=' * 60, use_color) + '\n')
    out.write(_c('bold', '  lswiz - Security Scan Report', use_color) + '\n')
    out.write(_c('bold', '=' * 60, use_color) + '\n\n')

    grade = results.get('server_grade', 'none')
    max_score = results.get('server_max_score', 0.0)
    total_cves = results.get('total_cves', 0)

    out.write('  Server Risk Grade: {}\n'.format(
        _c(grade, grade.upper(), use_color),
    ))
    out.write('  Max Risk Score:    {:.1f} / 10.0\n'.format(max_score))
    out.write('  Total CVEs:        {}\n'.format(total_cves))

    severity = results.get('severity_counts', {})
    out.write('  Breakdown:         ')
    parts = []
    for level in ['critical', 'high', 'medium', 'low']:
        count = severity.get(level, 0)
        if count > 0:
            parts.append(_c(level, '{} {}'.format(count, level), use_color))
    out.write(' | '.join(parts) if parts else 'none')
    out.write('\n\n')


def _print_vulnerable_packages(out, results, use_color):
    packages = results.get('packages', [])
    vulnerable = [p for p in packages if p.get('cves')]

    if not vulnerable:
        out.write('  No vulnerabilities found.\n\n')
        return

    out.write(_c('bold', '--- Vulnerable Packages ---', use_color) + '\n\n')

    # sort by risk score descending
    vulnerable.sort(key=lambda p: p.get('risk_score', 0), reverse=True)

    for pkg in vulnerable:
        name = pkg['name']
        version = pkg.get('version', '')
        source = pkg.get('source', '')
        status = pkg.get('status', '')
        score = pkg.get('risk_score', 0.0)
        grade = pkg.get('risk_grade', 'none')

        label = '{name} {ver}'.format(name=name, ver=version)
        out.write('  {} [{}] [{}] score={:.1f}\n'.format(
            _c(grade, label, use_color),
            source,
            status,
            score,
        ))

        for cve in pkg['cves']:
            cve_id = cve.get('cve_id', '')
            cvss = cve.get('cvss3_score', 0.0)
            ctx_score = cve.get('contextual_score', 0.0)
            desc = cve.get('description', '')
            if len(desc) > 80:
                desc = desc[:77] + '...'

            out.write('    {} CVSS={:.1f} CTX={:.1f} {}\n'.format(
                cve_id, cvss, ctx_score, desc,
            ))

        out.write('\n')


def _print_recommendations(out, results, use_color):
    packages = results.get('packages', [])
    has_recs = any(p.get('recommendations') for p in packages)

    if not has_recs:
        return

    out.write(_c('bold', '--- Recommendations ---', use_color) + '\n\n')

    for pkg in packages:
        recs = pkg.get('recommendations', [])
        if not recs:
            continue

        out.write('  {name}:\n'.format(name=pkg['name']))
        for rec in recs:
            priority = rec.get('priority', 'medium')
            desc = rec.get('description', '')
            out.write('    [{pri}] {desc}\n'.format(
                pri=_c(priority if priority == 'high' else 'medium', priority.upper(), use_color),
                desc=desc,
            ))
            for cmd in rec.get('commands', []):
                if cmd:
                    out.write('      {}\n'.format(_c('dim', cmd, use_color)))
        out.write('\n')


def _print_unused_clean(out, results, use_color):
    unused = results.get('unused_clean', [])
    if not unused:
        return

    out.write(_c('bold', '--- Unused Binaries (no CVEs) ---', use_color) + '\n')
    out.write('  The following {} binaries are installed but unused and have no known CVEs:\n'.format(
        len(unused),
    ))
    for name in sorted(unused):
        out.write('    {}\n'.format(name))
    out.write('\n')


def _print_migration(out, results, use_color):
    migration = results.get('migration_urgency', {})
    if not migration:
        return

    level = migration.get('level', 'MONITOR')
    reason = migration.get('reason', '')

    color = {
        'IMMEDIATE': 'critical',
        'URGENT': 'high',
        'PLANNED': 'medium',
        'ADVISORY': 'low',
        'MONITOR': 'none',
    }.get(level, 'none')

    out.write(_c('bold', '--- Migration Urgency ---', use_color) + '\n')
    out.write('  Level: {}\n'.format(_c(color, level, use_color)))
    out.write('  {}\n\n'.format(reason))


def _print_footer(out, results, use_color):
    out.write(_c('dim', '-' * 60, use_color) + '\n')
    out.write(_c('dim', '  Generated by lswiz - Linux System Wizard', use_color) + '\n')
    out.write(_c('dim', '  https://github.com/uzih05/lswiz', use_color) + '\n\n')
