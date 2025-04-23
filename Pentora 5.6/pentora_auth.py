#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Pentora - GUI-based vulnerability scanner with authentication
# Copyright (C) 2025 Pentora Team

"""
Pentora - Vulnerability Scanner with Authentication
"""

import sys
import os
import io

# Force UTF-8 encoding for stdout/stderr to handle Unicode characters
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add the current directory to the path to import pentora module
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from pentora.pentora_gui_auth import main

if __name__ == "__main__":
    main() 