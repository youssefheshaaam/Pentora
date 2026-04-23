# Module Description:
# This module detects stored (persistent) Cross-Site Scripting vulnerabilities
# where malicious scripts are stored on the target server and later displayed to
# other users. These are particularly dangerous as they affect all visitors to
# the compromised page, not just the user who triggered the payload.
from os.path import join as path_join
from typing import Optional, Tuple, Dict

from httpx import ReadTimeout, RequestError

from PentoraCore.main.log import log_red, log_orange, log_verbose
from PentoraCore.attack.attack import Attack, Mutator, random_string, Parameter, ParameterSituation
from PentoraCore.language.vulnerability import Messages
from PentoraCore.definitions.stored_xss import StoredXssFinding
from PentoraCore.definitions.stored_html_injection import StoredHtmlFinding
from PentoraCore.definitions.internal_error import InternalErrorFinding
from PentoraCore.definitions.resource_consumption import ResourceConsumptionFinding
from PentoraCore.model import PayloadInfo
from PentoraCore.net import Request, Response
from PentoraCore.net.xss_utils import generate_payloads, valid_xss_content_type, check_payload
from PentoraCore.net.csp_utils import has_strong_csp
from PentoraCore.parsers.html_parser import Html


class ModulePermanentxss(Attack):
    """
    Detect stored (aka permanent) Cross-Site Scripting vulnerabilities on the web server.
    """

    name = "permanentxss"
    require = ["xss"]
    PRIORITY = 6

    # Attempted payload injection from mod_xss.
    # key is tainted value, dict values are (mutated_request, parameter, flags)
    tried_xss: Dict[str, Tuple[Request, Parameter]] = {}

    # key = taint code, value = (evil request, payload info, parameter)
    successful_xss: Dict[str, Tuple[Request, PayloadInfo]] = {}

    PAYLOADS_FILE = path_join(Attack.DATA_DIR, "xssPayloads.ini")

    RANDOM_WEBSITE = f"https://{random_string(length=6)}.com/"

    @property
    def external_endpoint(self):
        return self.RANDOM_WEBSITE

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if not valid_xss_content_type(response) or response.status in (301, 302, 303):
            # If that content-type can't be interpreted as HTML by browsers then it is useless
            # Same goes for redirections
            return False

        if response.is_directory_redirection:
            return False

        return True

    async def attack(self, request: Request, response: Optional[Response] = None):
        """This method searches XSS which could be permanently stored in the web application"""
        headers = {}

        if request.referer:
            headers["referer"] = request.referer

        try:
            response = await self.crawler.async_send(Request(request.url), headers=headers)
            data = response.content
        except RequestError:
            self.network_errors += 1
            return

        html = Html(response.content, request.url)

        # Search in the page source for every taint code that was used previously by mod_xss
        for taint in self.tried_xss:
            input_request, parameter = self.tried_xss[taint]

            # Such situations should not occur as it would be stupid to block POST (or GET) requests for mod_xss
            # and not mod_permanentxss, but it is possible so let's filter that.
            if not self.do_get and input_request.method == "GET":
                continue

            if not self.do_post and input_request.method == "POST":
                continue

            if taint.lower() in data.lower():
                # Code found in the webpage !
                # Did mod_xss saw this as a reflected XSS ?
                if taint in self.successful_xss:
                    # Yes, it means XSS payloads were injected, not just tainted code.
                    # Either we are on the same vulnerability that mod_xss found or our injections appears at different
                    # places (which would be awkward)
                    evil_request, payload_info = self.successful_xss[taint]
                    # Using rules declared in the INI, check it we find the payload in the webpage
                    if check_payload(
                        self.DATA_DIR,
                        self.PAYLOADS_FILE,
                        self.external_endpoint,
                        self.proto_endpoint,
                        html,
                        payload_info,
                        taint
                    ):
                        # Success, this is a stored XSS / HTML injection vulnerability
                        finding = StoredXssFinding if payload_info.injection_type == "javascript" else StoredHtmlFinding
                        if request.path == evil_request.path:
                            description = (
                                f"{finding.name()} vulnerability found via injection "
                                f"in the parameter {parameter.name}"
                            )
                        else:
                            description = (
                                f"{finding.name()} vulnerability found in {request.url} by injecting"
                                f" the parameter {parameter.name} of {input_request.path}"
                            )
                        if has_strong_csp(response, html):
                            description += ".\nWarning: Content-Security-Policy is present!"

                        await self.add_high(
                            request_id=request.path_id,
                            finding_class=finding,
                            request=evil_request,
                            parameter=parameter.name,
                            info=description,
                        )

                        if parameter.is_qs_injection:
                            injection_msg = Messages.MSG_QS_INJECT
                        else:
                            injection_msg = Messages.MSG_PARAM_INJECT

                        log_red("---")
                        log_red(
                            injection_msg,
                            finding.name(),
                            request.path,
                            parameter.name
                        )

                        if has_strong_csp(response, html):
                            log_red("Warning: Content-Security-Policy is present!")

                        log_red(Messages.MSG_EVIL_REQUEST)
                        log_red(evil_request.http_repr())
                        log_red("---")

                # Here mod_xss did inject the tainted value but as it was not reflected in the same webpage it didn't
                # go further. It is now our job to send the payloads to webpage A and check the output in webpage B
                else:
                    payloads = generate_payloads(response.content, taint, self.PAYLOADS_FILE, self.external_endpoint)

                    if parameter.situation == ParameterSituation.QUERY_STRING:
                        method = "G"
                    elif parameter.situation == ParameterSituation.MULTIPART:
                        method = "F"
                    else:
                        method = "P"

                    await self.attempt_exploit(method, payloads, input_request, parameter.name, taint, request)

    def load_require(self, dependencies: list = None):
        if dependencies:
            for module in dependencies:
                if module.name == "xss":
                    self.successful_xss = module.successful_xss
                    self.tried_xss = module.tried_xss

    async def attempt_exploit(self, method, payloads, injection_request, parameter: str, taint: str, output_request):
        timeouted = False
        page = injection_request.path
        saw_internal_error = False
        output_url = output_request.url

        attack_mutator = Mutator(
            methods=method,
            qs_inject=self.must_attack_query_string,
            parameters=[parameter],
            skip=self.options.get("skipped_parameters")
        )

        for evil_request, xss_param, payload_info in attack_mutator.mutate(injection_request, payloads):
            log_verbose(f"[¨] {evil_request}")

            try:
                await self.crawler.async_send(evil_request)
            except ReadTimeout:
                self.network_errors += 1
                if timeouted:
                    continue

                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(evil_request.http_repr())
                log_orange("---")

                if xss_param.is_qs_injection:
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(xss_param.display_name)

                await self.add_medium(
                    request_id=injection_request.path_id,
                    finding_class=ResourceConsumptionFinding,
                    request=evil_request,
                    info=anom_msg,
                    parameter=xss_param.display_name,
                )
                timeouted = True
            except RequestError:
                self.network_errors += 1
                continue
            else:
                try:
                    response = await self.crawler.async_send(output_request)
                except RequestError:
                    self.network_errors += 1
                    continue

                html = Html(response.content, output_url)

                if (
                        not response.is_redirect and
                        valid_xss_content_type(response) and
                        check_payload(
                            self.DATA_DIR,
                            self.PAYLOADS_FILE,
                            self.external_endpoint,
                            self.proto_endpoint,
                            html,
                            payload_info,
                            taint
                        )
                ):

                    finding = StoredXssFinding if payload_info.injection_type == "javascript" else StoredHtmlFinding
                    if page == output_request.path:
                        description = (
                            f"{finding.name()} vulnerability found via injection "
                            f"in the parameter {xss_param.display_name}"
                        )
                    else:
                        description = (
                            f"{finding.name()} vulnerability found in {output_request.url} by injecting"
                            f" the parameter {parameter} of {page}"
                        )

                    if has_strong_csp(response, html):
                        description += ".\nWarning: Content-Security-Policy is present!"

                    await self.add_high(
                        request_id=injection_request.path_id,
                        finding_class=finding,
                        request=evil_request,
                        parameter=xss_param.display_name,
                        info=description,
                        response=response
                    )

                    if xss_param.is_qs_injection:
                        injection_msg = Messages.MSG_QS_INJECT
                    else:
                        injection_msg = Messages.MSG_PARAM_INJECT

                    log_red("---")
                    # TODO: use a more detailed description like the one used for the report
                    log_red(
                        injection_msg,
                        finding.name(),
                        output_url,
                        xss_param.display_name,
                    )

                    if has_strong_csp(response, html):
                        log_red("Warning: Content-Security-Policy is present!")

                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(evil_request.http_repr())
                    log_red("---")

                    # stop trying payloads and jump to the next parameter
                    break

                if response.is_server_error and not saw_internal_error:
                    if xss_param.is_qs_injection:
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(xss_param.display_name)

                    await self.add_high(
                        request_id=injection_request.path_id,
                        finding_class=InternalErrorFinding,
                        request=evil_request,
                        info=anom_msg,
                        parameter=xss_param.display_name,
                        response=response
                    )

                    log_orange("---")
                    log_orange(Messages.MSG_500, page)
                    log_orange(Messages.MSG_EVIL_REQUEST)
                    log_orange(evil_request.http_repr())
                    log_orange("---")
                    saw_internal_error = True
