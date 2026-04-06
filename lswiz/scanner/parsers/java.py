# -*- coding: utf-8 -*-
from __future__ import absolute_import
from lswiz.scanner.parsers.base import BaseParser


class JavaParser(BaseParser):
    """Parser for Java (OpenJDK / Oracle JDK)."""

    names = ['java']
    cpe_vendor = 'oracle'
    cpe_product = 'jdk'

    def extract_version(self, binary_path):
        # java -version outputs to stderr:
        #   openjdk version "1.8.0_382"
        #   java version "17.0.8"
        output = self.run_command([binary_path, '-version'])

        # try new format first: "17.0.8"
        version = self.match_version(output, r'version\s+"([\d.]+[^"]*)"')
        if version:
            # normalize 1.8.0_382 → 8.0.382
            if version.startswith('1.'):
                parts = version.split('.')
                if len(parts) >= 2:
                    major = parts[1]
                    rest = version.split('_')
                    if len(rest) > 1:
                        version = '{}.0.{}'.format(major, rest[1])
                    else:
                        version = major
        return version
