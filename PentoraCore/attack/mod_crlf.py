# Module Description:
# This module detects Carriage Return Line Feed (CRLF) injection vulnerabilities.
# CRLF injections occur when an attacker can inject CR and LF characters into HTTP
# headers, potentially allowing for HTTP response splitting, header injection, or
# other attacks that manipulate the HTTP response structure.

from typing import Optional

from httpx import ReadTimeout, HTTPStatusError, RequestError

from PentoraCore.attack.attack import Attack
from PentoraCore.language.vulnerability import Messages
from PentoraCore.definitions.crlf import CrlfFinding
from PentoraCore.definitions.resource_consumption import ResourceConsumptionFinding
from PentoraCore.model import PayloadInfo, str_to_payloadinfo
from PentoraCore.net import Request, Response
from PentoraCore.main.log import logging, log_blue, log_verbose, log_orange, log_red


class ModuleCrlf(Attack):
    """Detect Carriage Return Line Feed (CRLF) injection vulnerabilities."""
    # Won't work with PHP >= 4.4.2

    name = "crlf"
    MSG_VULN = "CRLF Injection"
    do_get = True
    do_post = True
    payloads = [PayloadInfo(payload="http://www.google.fr\r\npentora: 3.2.2 version")]

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        super().__init__(crawler, persister, attack_options, crawler_configuration)
        self.mutator = self.get_mutator()

    async def attack(self, request: Request, response: Optional[Response] = None):
        page = request.path

        for mutated_request, parameter, _payload in self.mutator.mutate(
                request,
                str_to_payloadinfo(["http://www.google.fr\r\npentora: 3.2.2 version"]),
        ):
            log_verbose(f"[¨] {mutated_request.url}")

            try:
                response = await self.crawler.async_send(mutated_request)
            except ReadTimeout:
                self.network_errors += 1
                await self.add_medium(
                    request_id=request.path_id,
                    finding_class=ResourceConsumptionFinding,
                    request=mutated_request,
                    parameter=parameter.display_name,
                    info="Timeout (" + parameter.display_name + ")",
                )

                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(mutated_request.http_repr())
                log_orange("---")
            except HTTPStatusError:
                self.network_errors += 1
                logging.error("Error: The server did not understand this request")
            except RequestError:
                self.network_errors += 1
            else:
                if "pentora" in response.headers:
                    await self.add_low(
                        request_id=request.path_id,
                        finding_class=CrlfFinding,
                        request=mutated_request,
                        parameter=parameter.display_name,
                        info=f"{self.MSG_VULN} via injection in the parameter {parameter.display_name}",
                        response=response,
                    )

                    if parameter.is_qs_injection:
                        injection_msg = Messages.MSG_QS_INJECT
                    else:
                        injection_msg = Messages.MSG_PARAM_INJECT

                    log_red("---")
                    log_red(
                        injection_msg,
                        self.MSG_VULN,
                        page,
                        parameter.display_name
                    )
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")
