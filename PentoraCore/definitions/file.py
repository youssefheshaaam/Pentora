#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class PathTraversalFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Path Traversal"

    @classmethod
    def description(cls) -> str:
        return (
            "This attack is known as Path or Directory Traversal. "
            "Its aim is the access to files and directories that are stored outside the web root folder. "
            "The attacker tries to explore the directories stored in the web server. "
            "The attacker uses some techniques, for instance, the manipulation of variables that reference files with "
            "'dot-dot-slash (../)' sequences and its variations to move up to root directory to navigate through "
            "the file system."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Path Traversal",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/"
                    "05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include"
                )
            },
            {
                "title": "Acunetix: What is a Directory Traversal attack?",
                "url": "https://www.acunetix.com/websitesecurity/directory-traversal/"
            },
            {
                "title": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                "url": "https://cwe.mitre.org/data/definitions/22.html"
            },
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Prefer working without user input when using file system calls. "
            "Use indexes rather than actual portions of file names when templating or using language files "
            "(eg: value 5 from the user submission = Czechoslovakian, rather than expecting the user to return "
            "'Czechoslovakian'). "
            "Ensure the user cannot supply all parts of the path - surround it with your path code. "
            "Validate the user's input by only accepting known good - do not sanitize the data. "
            "Use chrooted jails and code access policies to restrict where the files can be obtained or saved to."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-ATHZ-01"]
