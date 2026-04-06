# -*- coding: utf-8 -*-
from __future__ import absolute_import
from lswiz.scanner.parsers.base import BaseParser


class NginxParser(BaseParser):
    """Parser for nginx web server."""

    names = ['nginx']
    cpe_vendor = 'f5'
    cpe_product = 'nginx'

    def extract_version(self, binary_path):
        # nginx -v outputs to stderr: "nginx version: nginx/1.24.0"
        output = self.run_command([binary_path, '-v'])
        return self.match_version(output, r'nginx/([\d.]+)')
