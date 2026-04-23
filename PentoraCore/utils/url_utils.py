#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Pentora - GUI-based vulnerability scanner
# Copyright (C) 2025 Pentora Team

from urllib.parse import urlparse

def is_valid_url(url: str):
    """Verify if the url provided has the right format"""
    try:
        parts = urlparse(url)
    except ValueError:
        return False
    else:
        if parts.scheme in ("http", "https") and parts.netloc:
            return True
    return False

def fix_url_path(url: str):
    """Fix the url path if it's not defined"""
    return url if urlparse(url).path else url + '/'
