# -*- coding: utf-8 -*-
from __future__ import absolute_import
from lswiz.scanner.parsers.base import BaseParser


class RedisParser(BaseParser):
    """Parser for Redis."""

    names = ['redis-server', 'redis-cli']
    cpe_vendor = 'redis'
    cpe_product = 'redis'

    def extract_version(self, binary_path):
        # redis-server --version → "Redis server v=7.0.12 sha=..."
        # redis-cli --version → "redis-cli 7.0.12"
        output = self.run_command([binary_path, '--version'])

        # try server format first
        version = self.match_version(output, r'v=([\d.]+)')
        if version:
            return version

        # cli format
        return self.match_version(output, r'redis-cli\s+([\d.]+)')
