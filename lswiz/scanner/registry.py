# -*- coding: utf-8 -*-
"""Parser registry — auto-discovers and indexes all dedicated parsers."""
from __future__ import absolute_import
import os
import importlib
import pkgutil

from lswiz.scanner.parsers.base import BaseParser
from lswiz.scanner.parsers.generic import GenericParser

_registry = {}  # binary_name -> parser_instance
_loaded = False


def _load_parsers():
    """Import all parser modules and register them by binary name."""
    global _loaded
    if _loaded:
        return

    parsers_pkg = importlib.import_module('lswiz.scanner.parsers')
    pkg_path = os.path.dirname(parsers_pkg.__file__)

    for importer, modname, ispkg in pkgutil.iter_modules([pkg_path]):
        if modname in ('base', 'generic', '__init__'):
            continue
        module = importlib.import_module('lswiz.scanner.parsers.' + modname)
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type)
                    and issubclass(attr, BaseParser)
                    and attr is not BaseParser
                    and hasattr(attr, 'names')):
                instance = attr()
                for name in instance.names:
                    _registry[name] = instance

    _loaded = True


def get_parser(binary_name):
    """Get the dedicated parser for a binary name.

    Args:
        binary_name: filename of the binary (e.g. 'nginx')

    Returns:
        BaseParser instance (dedicated or GenericParser fallback)
    """
    _load_parsers()
    parser = _registry.get(binary_name)
    if parser:
        return parser
    return GenericParser()


def is_dedicated(binary_name):
    """Check if a dedicated parser exists for this binary.

    Args:
        binary_name: filename of the binary

    Returns:
        bool
    """
    _load_parsers()
    return binary_name in _registry


def list_supported():
    """List all binary names with dedicated parsers.

    Returns:
        list[str]: sorted list of supported binary names
    """
    _load_parsers()
    return sorted(_registry.keys())
