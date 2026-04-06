# -*- coding: utf-8 -*-
from __future__ import absolute_import
import argparse
import sys

from lswiz import __version__
from lswiz.core.config import load_config
from lswiz.core.logger import setup_logger
from lswiz.core.privilege import check_root


def cmd_scan(args, config, logger):
    """Run scan: preflight + package collection + CVE matching."""
    from lswiz.preflight.network import check_connectivity
    from lswiz.preflight.repo import check_and_fix_repos
    from lswiz.scanner.rpm import scan_rpm_packages
    from lswiz.scanner.manual import scan_manual_binaries
    from lswiz.scanner.status import classify_status
    from lswiz.cve.redhat import match_rpm_cves
    from lswiz.cve.nvd import match_manual_cves

    logger.info('=== Phase 1: Preflight ===')
    check_connectivity(config, logger)
    check_and_fix_repos(config, logger)

    logger.info('=== Phase 2: Scan ===')
    rpm_packages = []
    manual_binaries = []

    if config['scan']['rpm']:
        rpm_packages = scan_rpm_packages(logger)
        logger.info('Found %d RPM packages', len(rpm_packages))

    if config['scan']['manual']:
        manual_binaries = scan_manual_binaries(config, logger)
        logger.info('Found %d manual binaries', len(manual_binaries))

    logger.info('=== Classifying binary status ===')
    all_packages = rpm_packages + manual_binaries
    classify_status(all_packages, logger)

    logger.info('=== Phase 3: CVE Matching ===')
    if rpm_packages:
        match_rpm_cves(rpm_packages, config, logger)
    if manual_binaries:
        match_manual_cves(manual_binaries, config, logger)

    cve_count = sum(len(p.get('cves', [])) for p in all_packages)
    logger.info('Total CVEs found: %d', cve_count)

    return all_packages


def cmd_score(args, config, logger):
    """Run full pipeline up to risk scoring."""
    from lswiz.scoring.risk import calculate_risk_scores

    packages = cmd_scan(args, config, logger)

    logger.info('=== Phase 4: Risk Scoring ===')
    results = calculate_risk_scores(packages, config, logger)
    return results


def cmd_doctor(args, config, logger):
    """Run full pipeline up to doctor recommendations."""
    from lswiz.doctor import recommend_mitigations

    results = cmd_score(args, config, logger)

    logger.info('=== Phase 5: Doctor ===')
    recommendations = recommend_mitigations(results, config, logger)
    return recommendations


def cmd_report(args, config, logger):
    """Run full pipeline and generate report."""
    from lswiz.report import generate_report

    recommendations = cmd_doctor(args, config, logger)

    logger.info('=== Phase 6: Report ===')
    fmt = args.format if hasattr(args, 'format') and args.format else config['report']['format']
    generate_report(recommendations, fmt, config, logger)


def cmd_full(args, config, logger):
    """Run the complete pipeline."""
    args.format = getattr(args, 'format', None) or config['report']['format']
    cmd_report(args, config, logger)


def build_parser():
    """Build argparse parser."""
    parser = argparse.ArgumentParser(
        prog='lswiz',
        description='Linux System Wizard - CentOS 7 EOL security vulnerability scanner',
    )
    parser.add_argument(
        '-V', '--version',
        action='version',
        version='lswiz {}'.format(__version__),
    )
    parser.add_argument(
        '-c', '--config',
        help='path to config file',
        default=None,
    )

    sub = parser.add_subparsers(dest='command')

    sub.add_parser('scan', help='collect packages and match CVEs')
    sub.add_parser('score', help='scan + risk scoring')
    sub.add_parser('doctor', help='scan + score + mitigation recommendations')

    report_parser = sub.add_parser('report', help='full pipeline + generate report')
    report_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json', 'html'],
        default=None,
        help='report output format (default: from config)',
    )

    full_parser = sub.add_parser('full', help='run complete pipeline')
    full_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json', 'html'],
        default=None,
        help='report output format (default: from config)',
    )

    return parser


COMMANDS = {
    'scan': cmd_scan,
    'score': cmd_score,
    'doctor': cmd_doctor,
    'report': cmd_report,
    'full': cmd_full,
}


def main():
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    config = load_config(args.config)
    logger = setup_logger(config)

    check_root()

    handler = COMMANDS.get(args.command)
    if handler:
        try:
            handler(args, config, logger)
        except KeyboardInterrupt:
            logger.info('Interrupted by user')
            sys.exit(130)
        except Exception as e:
            logger.error('Fatal error: %s', str(e))
            sys.exit(1)


if __name__ == '__main__':
    main()
