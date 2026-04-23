#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class RedirectFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Open Redirect"

    @classmethod
    def description(cls) -> str:
        return (
            "Unvalidated redirects and forwards are possible when a web application accepts untrusted input that could "
            "cause the web application to redirect the request to a URL contained within untrusted input. "
            "By modifying untrusted URL input to a malicious site, "
            "an attacker may successfully launch a phishing scam and steal user credentials."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "Unvalidated Redirects and Forwards Cheat Sheet",
                "url": (
                    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                )
            },
            {
                "title": "Acunetix: What Are Open Redirects?",
                "url": "https://www.acunetix.com/blog/web-security-zone/what-are-open-redirects/"
            },
            {
                "title": "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
                "url": "https://cwe.mitre.org/data/definitions/601.html"
            },
            {
                "title": "OWASP: Client-side URL Redirect",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Force all redirects to first go through a page notifying users that they are going off of your site, "
            "and have them click a link to confirm."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CLNT-04"]
