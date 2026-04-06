# -*- coding: utf-8 -*-
from __future__ import absolute_import
from lswiz.scanner.parsers.base import BaseParser


class PythonParser(BaseParser):
    """Parser for Python interpreter."""

    names = ['python', 'python2', 'python3', 'python2.7', 'python3.6']
    cpe_vendor = 'python'
    cpe_product = 'python'

    def extract_version(self, binary_path):
        # python --version → "Python 3.6.8"
        # python2 may output to stderr
        output = self.run_command([binary_path, '--version'])
        return self.match_version(output, r'Python\s+([\d.]+)')
