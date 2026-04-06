# -*- coding: utf-8 -*-
"""HTML report generator."""
from __future__ import absolute_import
import os
import sys
from datetime import datetime


HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>lswiz Security Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         max-width: 960px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
  .header {{ background: #1a1a2e; color: #fff; padding: 24px; border-radius: 8px; margin-bottom: 20px; }}
  .header h1 {{ margin: 0 0 8px; }}
  .grade {{ font-size: 2em; font-weight: bold; }}
  .grade-critical {{ color: #ff4444; }}
  .grade-high {{ color: #ffaa00; }}
  .grade-medium {{ color: #ffdd57; }}
  .grade-low {{ color: #00d1b2; }}
  .grade-none {{ color: #48c774; }}
  .card {{ background: #fff; border-radius: 8px; padding: 16px; margin-bottom: 12px;
           box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .card h3 {{ margin-top: 0; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;
            font-weight: bold; color: #fff; margin-right: 4px; }}
  .badge-critical {{ background: #ff4444; }}
  .badge-high {{ background: #ffaa00; }}
  .badge-medium {{ background: #ffdd57; color: #333; }}
  .badge-low {{ background: #00d1b2; }}
  .badge-rpm {{ background: #6c757d; }}
  .badge-manual {{ background: #007bff; }}
  .badge-running {{ background: #28a745; }}
  .badge-inactive {{ background: #ffc107; color: #333; }}
  .badge-unused {{ background: #6c757d; }}
  table {{ width: 100%; border-collapse: collapse; margin: 8px 0; }}
  th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid #eee; }}
  th {{ background: #f8f9fa; }}
  .cmd {{ background: #f1f3f5; padding: 8px 12px; border-radius: 4px; font-family: monospace;
          font-size: 0.9em; margin: 4px 0; white-space: pre-wrap; }}
  .footer {{ text-align: center; color: #888; font-size: 0.85em; margin-top: 24px; }}
  .migration {{ padding: 16px; border-radius: 8px; margin-bottom: 16px; }}
  .migration-IMMEDIATE {{ background: #ffe0e0; border: 2px solid #ff4444; }}
  .migration-URGENT {{ background: #fff3e0; border: 2px solid #ffaa00; }}
  .migration-PLANNED {{ background: #fffde0; border: 2px solid #ffdd57; }}
  .migration-ADVISORY {{ background: #e0f7fa; border: 2px solid #00d1b2; }}
  .migration-MONITOR {{ background: #e8f5e9; border: 2px solid #48c774; }}
</style>
</head>
<body>
{content}
</body>
</html>'''


def generate_html_report(results, config, logger):
    """Generate HTML report."""
    content = []

    # header
    grade = results.get('server_grade', 'none')
    content.append('<div class="header">')
    content.append('<h1>lswiz Security Report</h1>')
    content.append('<span class="grade grade-{g}">{g}</span>'.format(g=grade))
    content.append(' Score: {:.1f}/10.0 | CVEs: {}'.format(
        results.get('server_max_score', 0.0),
        results.get('total_cves', 0),
    ))
    content.append('</div>')

    # migration urgency
    migration = results.get('migration_urgency', {})
    if migration:
        level = migration.get('level', 'MONITOR')
        content.append('<div class="migration migration-{l}">'.format(l=level))
        content.append('<strong>Migration Urgency: {}</strong>'.format(level))
        content.append('<p>{}</p>'.format(_escape(migration.get('reason', ''))))
        content.append('</div>')

    # vulnerable packages
    packages = results.get('packages', [])
    vulnerable = sorted(
        [p for p in packages if p.get('cves')],
        key=lambda p: p.get('risk_score', 0),
        reverse=True,
    )

    if vulnerable:
        content.append('<h2>Vulnerable Packages ({})</h2>'.format(len(vulnerable)))
        for pkg in vulnerable:
            _render_package_card(pkg, content)

    # recommendations
    has_recs = any(p.get('recommendations') for p in packages)
    if has_recs:
        content.append('<h2>Recommendations</h2>')
        for pkg in packages:
            recs = pkg.get('recommendations', [])
            if not recs:
                continue
            content.append('<div class="card">')
            content.append('<h3>{}</h3>'.format(_escape(pkg['name'])))
            for rec in recs:
                content.append('<p><strong>[{}]</strong> {}</p>'.format(
                    _escape(rec.get('priority', '').upper()),
                    _escape(rec.get('description', '')),
                ))
                cmds = rec.get('commands', [])
                if cmds:
                    content.append('<div class="cmd">{}</div>'.format(
                        _escape('\n'.join(cmds)),
                    ))
            content.append('</div>')

    # unused clean
    unused = results.get('unused_clean', [])
    if unused:
        content.append('<h2>Unused Binaries (no CVEs) &mdash; {} found</h2>'.format(len(unused)))
        content.append('<div class="card"><ul>')
        for name in sorted(unused):
            content.append('<li>{}</li>'.format(_escape(name)))
        content.append('</ul></div>')

    # footer
    content.append('<div class="footer">')
    content.append('Generated by lswiz at {} | '.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    content.append('github.com/uzih05/lswiz')
    content.append('</div>')

    html = HTML_TEMPLATE.format(content='\n'.join(content))

    # save to file
    output_dir = config.get('report', {}).get('output_dir', '/tmp/lswiz-reports')
    try:
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)
    except OSError:
        output_dir = '/tmp'

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = 'lswiz_report_{}.html'.format(timestamp)
    filepath = os.path.join(output_dir, filename)

    try:
        with open(filepath, 'w') as f:
            f.write(html)
        logger.info('HTML report saved: %s', filepath)
        sys.stdout.write('Report saved: {}\n'.format(filepath))
    except IOError as e:
        # fallback to stdout
        logger.warning('Could not save file, printing to stdout: %s', str(e))
        sys.stdout.write(html)


def _render_package_card(pkg, content):
    """Render a single package card."""
    name = _escape(pkg['name'])
    version = _escape(pkg.get('version', ''))
    source = pkg.get('source', '')
    status = pkg.get('status', '')
    grade = pkg.get('risk_grade', 'none')
    score = pkg.get('risk_score', 0.0)

    content.append('<div class="card">')
    content.append('<h3>{} {}'.format(name, version))
    content.append(' <span class="badge badge-{}">{}</span>'.format(source, source.upper()))
    content.append(' <span class="badge badge-{}">{}</span>'.format(status.lower(), status))
    content.append(' <span class="badge badge-{}">Score: {:.1f}</span>'.format(grade, score))
    content.append('</h3>')

    # CVE table
    cves = pkg.get('cves', [])
    if cves:
        content.append('<table>')
        content.append('<tr><th>CVE</th><th>CVSS</th><th>Context</th><th>Description</th></tr>')
        for cve in cves:
            desc = _escape(cve.get('description', ''))
            if len(desc) > 100:
                desc = desc[:97] + '...'
            content.append(
                '<tr><td><a href="{url}">{id}</a></td>'
                '<td>{cvss:.1f}</td><td>{ctx:.1f}</td><td>{desc}</td></tr>'.format(
                    url=_escape(cve.get('resource_url', '')),
                    id=_escape(cve.get('cve_id', '')),
                    cvss=cve.get('cvss3_score', 0.0),
                    ctx=cve.get('contextual_score', 0.0),
                    desc=desc,
                )
            )
        content.append('</table>')

    content.append('</div>')


def _escape(text):
    """Basic HTML escaping."""
    return (
        str(text)
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
    )
