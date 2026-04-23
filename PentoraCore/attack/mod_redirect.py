from typing import Optional
from urllib.parse import urlparse

from httpx import RequestError, InvalidURL

from PentoraCore.main.log import log_red, log_verbose
from PentoraCore.attack.attack import Attack
from PentoraCore.language.vulnerability import Messages
from PentoraCore.definitions.redirect import RedirectFinding
from PentoraCore.model import str_to_payloadinfo
from PentoraCore.net import Request, Response
from PentoraCore.parsers.html_parser import Html


class ModuleRedirect(Attack):
    """Detect Open Redirect vulnerabilities."""
    # Won't work with PHP >= 4.4.2

    name = "redirect"
    MSG_VULN = "Open Redirect"
    do_get = True
    do_post = False

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        super().__init__(crawler, persister, attack_options, crawler_configuration)
        self.mutator = self.get_mutator()

    async def attack(self, request: Request, response: Optional[Response] = None):
        page = request.path

        for mutated_request, parameter, __ in self.mutator.mutate(
                request,
                str_to_payloadinfo(["https://openbugbounty.org/", "//openbugbounty.org/"]),
        ):
            log_verbose(f"[¨] {mutated_request.url}")

            try:
                response = await self.crawler.async_send(mutated_request)
            except (RequestError, InvalidURL):
                self.network_errors += 1
                continue

            html = Html(response.content, mutated_request.url)
            all_redirections = {response.redirection_url} | html.all_redirections
            if any(urlparse(url).netloc.endswith("openbugbounty.org") for url in all_redirections):
                await self.add_low(
                    request_id=request.path_id,
                    finding_class=RedirectFinding,
                    request=mutated_request,
                    parameter=parameter.display_name,
                    info=f"{self.MSG_VULN} via injection in the parameter {parameter.display_name}",
                    response=response
                )

                if not parameter.is_qs_injection:
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
