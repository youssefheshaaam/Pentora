#!/usr/bin/env python3
# -*- coding: utf-8 -*-



import gettext
import os
import locale

# Define the translation function
def _(text):
    """Translate the given text using gettext."""
    return text

# Initialize gettext
def init_gettext():
    """Initialize gettext for internationalization."""
    global _
    locale_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "language", "locale")
    
    # Get the default locale
    try:
        lang, _ = locale.getdefaultlocale()
    except (ValueError, AttributeError):
        lang = None
    
    if lang:
        try:
            translation = gettext.translation("pentora", locale_dir, [lang])
            _ = translation.gettext
        except (IOError, OSError):
            # Fallback to default
            _ = gettext.gettext
    else:
        _ = gettext.gettext

# Initialize gettext at module load time
init_gettext()
