# -*- coding: utf-8 -*-
from __future__ import absolute_import
from lswiz.scanner.parsers.base import BaseParser


class NodeParser(BaseParser):
    """Parser for Node.js."""

    names = ['node', 'nodejs']
    cpe_vendor = 'nodejs'
    cpe_product = 'node.js'

    def extract_version(self, binary_path):
        # node --version → "v18.17.0"
        output = self.run_command([binary_path, '--version'])
        return self.match_version(output, r'v?([\d.]+)')
