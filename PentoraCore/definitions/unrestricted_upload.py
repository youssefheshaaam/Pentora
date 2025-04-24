#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class UnrestrictedUploadFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Unrestricted File Upload"

    @classmethod
    def description(cls) -> str:
        return (
            "File upload vulnerabilities are when a web server allows users to upload files to its filesystem without "
            "sufficiently validating things like their name, type, contents, or size. Failing to properly enforce "
            "restrictions on these could allow an attacker to upload potentially dangerous files. "
            "This could even include server-side script files that enable remote code execution."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "HackTricks: File Upload",
                "url": "https://book.hacktricks.xyz/pentesting-web/file-upload"
            },
            {
                "title": "PortSwigger : File upload vulnerabilities",
                "url": "https://portswigger.net/web-security/file-upload"
            },
            {
                "title": "CWE-434: Unrestricted Upload of File with Dangerous Type",
                "url": "https://cwe.mitre.org/data/definitions/434.html"
            },
            {
                "title": "OWASP: Test Upload of Unexpected File Types",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/10-Business_Logic_Testing/"
                    "08-Test_Upload_of_Unexpected_File_Types"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Check the file extension against a whitelist of permitted extensions rather than a blacklist of "
            "prohibited ones. Make sure the filename doesn't contain any substrings that may be interpreted as a "
            "directory or a traversal sequence (../). "
            "Rename uploaded files to avoid collisions that may cause existing files to be overwritten. "
            "Do not upload files to the server's permanent filesystem until they have been fully validated."
        )

    @classmethod
    def short_name(cls) -> str:
        return "Unrestricted Upload"

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        # CWE-434: Unrestricted Upload of File with Dangerous Type
        return ["WSTG-BUSL-08"]
