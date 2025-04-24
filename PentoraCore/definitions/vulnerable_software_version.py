#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from typing import List

from PentoraCore.definitions.base import FindingBase


class VulnerableSoftwareFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Vulnerable software"

    @classmethod
    def description(cls) -> str:
        return (
            "The detected software in its installed version is known to be vulnerable to one or more vulnerabilities."
        )

    @classmethod
    def references(cls) -> list:
        return []

    @classmethod
    def solution(cls) -> str:
        return (
            "Update the software to its latest version or applied security patches."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return []
