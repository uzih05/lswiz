# -*- coding: utf-8 -*-
from __future__ import absolute_import
from lswiz.scanner.parsers.base import BaseParser


class HttpdParser(BaseParser):
    """Parser for Apache HTTP Server."""

    names = ['httpd', 'apache2']
    cpe_vendor = 'apache'
    cpe_product = 'http_server'

    def extract_version(self, binary_path):
        # httpd -v → "Server version: Apache/2.4.6 (CentOS)"
        output = self.run_command([binary_path, '-v'])
        return self.match_version(output, r'Apache/([\d.]+)')
