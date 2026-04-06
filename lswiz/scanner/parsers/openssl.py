# -*- coding: utf-8 -*-
from __future__ import absolute_import
from lswiz.scanner.parsers.base import BaseParser


class OpensslParser(BaseParser):
    """Parser for OpenSSL."""

    names = ['openssl']
    cpe_vendor = 'openssl'
    cpe_product = 'openssl'

    def extract_version(self, binary_path):
        # openssl version → "OpenSSL 1.0.2k-fips  26 Jan 2017"
        output = self.run_command([binary_path, 'version'])
        return self.match_version(output, r'OpenSSL\s+([\d.]+[a-z]*)')
