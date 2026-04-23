# Module Description:
# This module detects Cross-Site Request Forgery (CSRF) vulnerabilities by analyzing
# forms for the absence of anti-CSRF tokens. CSRF vulnerabilities allow attackers to
# trick users into performing unwanted actions on authenticated websites by exploiting
# the trust that a site has in a user's browser.
from collections import Counter
from typing import Optional
import math
from httpx import RequestError

from PentoraCore.attack.attack import Attack
from PentoraCore.definitions.csrf import CsrfFinding
from PentoraCore.net import Request
from PentoraCore.net.crawler import Response
from PentoraCore.main.log import log_red


class ModuleCsrf(Attack):
    """
    Detect forms missing Cross-Site Request Forgery protections (CSRF tokens).
    """

    name = "csrf"

    do_get = False
    do_post = True

    csrf_string = None

    MIN_ENTROPY = 3
    MIN_LENGTH = 8

    TOKEN_FORM_STRINGS = [
        "authenticity_token", "_token", "csrf_token", "csrfname", "csrftoken", "anticsrf",
        "__requestverificationtoken", "token", "csrf", "_csrf_token", "xsrf_token",
        "_csrf", "csrf-token", "xsrf-token", "_wpnonce", "csrfmiddlewaretoken",
        "__csrf_token__", "csrfkey"
    ]

    TOKEN_HEADER_STRINGS = [
        "csrf-token", "x-csrf-token", "xsrf-token", "x-xsrf-token", "csrfp-token",
        "anti-csrf-token", "x-csrf-header", "x-xsrf-header", "x-csrf-protection"
    ]

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, crawler_configuration)
        # list to ensure only one occurrence per (vulnerable url/post_keys) tuple
        self.already_vulnerable = []

    @staticmethod
    def entropy(string: str):
        # Shannon entropy calculation
        # https://stackoverflow.com/questions/15450192/fastest-way-to-compute-entropy-in-python
        probabilities = [n_x / len(string) for x, n_x in Counter(string).items()]
        e_x = [-p_x * math.log(p_x, 2) for p_x in probabilities]
        return sum(e_x)

    def is_csrf_present(self, request: Request, response: Response):
        """Check whether anti-csrf token is present"""
        if request.is_json:
            return None

        # Look for anti-csrf token in form params
        for param in request.post_params:
            if param[0].lower() in self.TOKEN_FORM_STRINGS:
                self.csrf_string = param[0]
                return param[1]

        # Look for anti-csrf token in HTTP response headers
        if response.headers:
            for header in response.headers:
                if header.lower() in self.TOKEN_HEADER_STRINGS:
                    self.csrf_string = header
                    return response.headers[header]

        # Look for anti-csrf token in HTTP request headers
        if request.headers:
            for header in request.headers:
                if header.lower() in self.TOKEN_HEADER_STRINGS:
                    self.csrf_string = header
                    return request.headers[header]

        return None

    def is_csrf_robust(self, csrf_value):
        """Check whether anti-csrf token is robust enough"""

        # csrf value length is too short
        if len(csrf_value) < self.MIN_LENGTH:
            return False

        # csrf value entropy is too low, i.e. csrf value is too predictive
        if self.entropy(csrf_value) < self.MIN_ENTROPY:
            return False

        return True

    @staticmethod
    def is_same_response(original_response: Response, mutated_response: Response):
        """Check whether mutated_response status and content are identical to those of original_response"""

        if original_response.status != mutated_response.status:
            return False

        if original_response.content != mutated_response.content:  # TODO: Maybe too strict
            return False

        return True

    async def is_csrf_verified(self, request: Request, response: Response):
        """Check whether anti-csrf token is verified (backend) after submitting request"""

        # Replace anti-csrf token value from form with "pentora"
        mutated_post_params = [
            param if param[0] != self.csrf_string else [self.csrf_string, "pentora"]
            for param in request.post_params
        ]

        # Replace anti-csrf token value from headers with "pentora"
        special_headers = {}
        if response.headers and self.csrf_string in response.headers:
            special_headers[self.csrf_string] = "pentora"

        # Replace anti-csrf token value from request headers with "pentora"
        if request.headers and self.csrf_string in request.headers:
            special_headers[self.csrf_string] = "pentora"

        mutated_request = Request(
            path=request.path,
            method=request.method,
            get_params=request.get_params,
            post_params=mutated_post_params,
            file_params=request.file_params,
            referer=request.referer,
            link_depth=request.link_depth
        )

        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=True, headers=request.headers)
        except RequestError:
            # We can't compare so act like it is secure
            self.network_errors += 1
            return True

        try:
            mutated_response: Response = await self.crawler.async_send(
                mutated_request,
                headers=special_headers,
                follow_redirects=True
            )
        except RequestError:
            # Do not log anything: the payload is not harmful enough for such behavior
            self.network_errors += 1
        else:
            return not self.is_same_response(response, mutated_response)

        return True

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if request.method != "POST":
            return False

        if response.is_directory_redirection:
            return False

        # JSON requests can only be sent using JS with same-origin policy in place
        # so, it is unlikely that a CSRF is possible. Let's filter those requests to prevent false positives
        if request.is_json:
            return False

        if (request.url, request.post_keys) in self.already_vulnerable:
            return False

        return True

    async def attack(self, request: Request, response: Optional[Response] = None):
        csrf_value = self.is_csrf_present(request, response)

        # check if token is present
        if not csrf_value:
            vuln_message = "Lack of anti CSRF token"
        elif not await self.is_csrf_verified(request, response):
            vuln_message = f"CSRF token '{self.csrf_string}' is not properly checked in backend"
        elif not self.is_csrf_robust(csrf_value):
            vuln_message = f"CSRF token '{self.csrf_string}' might be easy to predict"
        else:
            return

        self.already_vulnerable.append((request.url, request.post_keys))

        log_red("---")
        log_red(vuln_message)
        log_red(request.http_repr())
        log_red("---")

        await self.add_medium(
            request_id=request.path_id,
            finding_class=CsrfFinding,
            request=request,
            info=vuln_message,
        )
