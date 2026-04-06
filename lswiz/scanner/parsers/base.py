# -*- coding: utf-8 -*-
"""Base class for binary version parsers."""
from __future__ import absolute_import
import subprocess
import re


class BaseParser(object):
    """Abstract base for binary-specific version parsers.

    Subclasses must define:
        names (list[str]): binary names this parser handles (e.g. ['nginx'])
        cpe_vendor (str): CPE vendor string (e.g. 'f5')
        cpe_product (str): CPE product string (e.g. 'nginx')

    Subclasses must implement:
        extract_version(binary_path) -> str or None
    """

    names = []
    cpe_vendor = ''
    cpe_product = ''

    def extract_version(self, binary_path):
        """Extract version string from binary.

        Args:
            binary_path: absolute path to the binary

        Returns:
            str: version string (e.g. '1.24.0') or None if extraction fails
        """
        raise NotImplementedError

    def build_cpe(self, version):
        """Build CPE 2.3 string from extracted version.

        Returns:
            str: CPE string or empty string if vendor/product not set
        """
        if not self.cpe_vendor or not self.cpe_product or not version:
            return ''
        return 'cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*'.format(
            vendor=self.cpe_vendor,
            product=self.cpe_product,
            version=version,
        )

    def run_command(self, args, timeout=5):
        """Run a command and return stdout+stderr combined.

        Args:
            args: command arguments list
            timeout: seconds before kill

        Returns:
            str: combined output or empty string on failure
        """
        try:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            stdout, _ = proc.communicate()
            return stdout.decode('utf-8', errors='replace').strip()
        except (OSError, subprocess.SubprocessError):
            return ''

    def match_version(self, text, pattern):
        """Extract version from text using regex pattern.

        Args:
            text: output text to search
            pattern: regex with a capture group for version

        Returns:
            str: matched version or None
        """
        m = re.search(pattern, text)
        if m:
            return m.group(1)
        return None
