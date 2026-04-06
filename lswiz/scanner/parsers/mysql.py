# -*- coding: utf-8 -*-
from __future__ import absolute_import
from lswiz.scanner.parsers.base import BaseParser


class MysqlParser(BaseParser):
    """Parser for MySQL / MariaDB."""

    names = ['mysql', 'mysqld', 'mariadb', 'mariadbd']
    cpe_vendor = ''
    cpe_product = ''

    def extract_version(self, binary_path):
        # mysql --version → "mysql  Ver 15.1 Distrib 5.5.68-MariaDB, ..."
        # mysqld --version → "mysqld  Ver 5.5.68-MariaDB ..."
        output = self.run_command([binary_path, '--version'])

        # check MariaDB first
        mariadb_ver = self.match_version(output, r'MariaDB[-, ]+([\d.]+)')
        if mariadb_ver:
            self.cpe_vendor = 'mariadb'
            self.cpe_product = 'mariadb'
            return mariadb_ver

        # MySQL
        mysql_ver = self.match_version(output, r'Ver\s+([\d.]+)')
        if mysql_ver:
            self.cpe_vendor = 'oracle'
            self.cpe_product = 'mysql'
            return mysql_ver

        return None
