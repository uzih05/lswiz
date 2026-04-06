# -*- coding: utf-8 -*-
from __future__ import absolute_import
import os
import sys


def check_root():
    """Check if running as root. Print warning if not.

    Returns:
        bool: True if running as root
    """
    if os.geteuid() == 0:
        return True

    print('[WARNING] lswiz is not running as root.')
    print('  Some features may not work correctly:')
    print('  - RPM database access may be limited')
    print('  - Binary scanning in system paths may be incomplete')
    print('  - Service status detection may fail')
    print('')
    print('  Run with: sudo lswiz <command>')
    print('')
    return False
