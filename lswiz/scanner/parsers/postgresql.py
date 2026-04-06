# -*- coding: utf-8 -*-
from __future__ import absolute_import
from lswiz.scanner.parsers.base import BaseParser


class PostgresqlParser(BaseParser):
    """Parser for PostgreSQL."""

    names = ['postgres', 'pg_config', 'psql']
    cpe_vendor = 'postgresql'
    cpe_product = 'postgresql'

    def extract_version(self, binary_path):
        # postgres --version → "postgres (PostgreSQL) 14.9"
        # psql --version → "psql (PostgreSQL) 14.9"
        # pg_config --version → "PostgreSQL 14.9"
        output = self.run_command([binary_path, '--version'])
        return self.match_version(output, r'(?:PostgreSQL)\)?\s+([\d.]+)')
