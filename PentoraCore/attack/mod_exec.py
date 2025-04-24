# Module Description:
# This module detects command injection vulnerabilities by testing parameters
# that might be used to execute system commands. Command injection can allow
# attackers to execute arbitrary commands on the host operating system, potentially
# leading to complete system compromise.
from os.path import join as path_join
from typing import Optional, Iterator

from httpx import ReadTimeout, RequestError

from PentoraCore.main.log import log_red, log_verbose, log_orange
from PentoraCore.attack.attack import Attack, Parameter
from PentoraCore.language.vulnerability import Messages
from PentoraCore.definitions.exec import CommandExecutionFinding
from PentoraCore.model import PayloadInfo
from PentoraCore.net.response import Response
from PentoraCore.definitions.resource_consumption import ResourceConsumptionFinding
from PentoraCore.definitions.internal_error import InternalErrorFinding
from PentoraCore.net import Request
from PentoraCore.parsers.ini_payload_parser import IniPayloadReader, replace_tags


class ModuleExec(Attack):
    """
    Detect scripts vulnerable to command and/or code execution.
    """
    name = "exec"

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        super().__init__(crawler, persister, attack_options, crawler_configuration)
        self.false_positive_timeouts = set()
        self.mutator = self.get_mutator()

    def get_payloads(self, _: Optional[Request] = None, __: Optional[Parameter] = None) -> Iterator[PayloadInfo]:
        """Load the payloads from the specified file"""
        parser = IniPayloadReader(path_join(self.DATA_DIR, "execPayloads.ini"))
        parser.add_key_handler("payload", replace_tags)
        parser.add_key_handler("rules", lambda x: x.splitlines() if x else [])

        yield from parser

    @staticmethod
    def _find_warning_in_response(data) -> str:
        warnings_and_infos = {
            "eval()'d code</b> on line <b>": "Warning eval()",
            "Cannot execute a blank command in": "Warning exec",
            "sh: command substitution:": "Warning exec",
            "Warning: usort()": "Warning usort()",
            "Warning: assert():": "Warning assert",
            "Failure evaluating code:": "Evaluation warning"
        }
        for warning, vuln_info in warnings_and_infos.items():
            if warning in data:
                return vuln_info
        return ""

    async def attack(self, request: Request, response: Optional[Response] = None):
        warned = False
        timeouted = False
        page = request.path
        saw_internal_error = False
        current_parameter = None
        vulnerable_parameter = False
        vulnerable_reversed_parameter = False

        for mutated_request, parameter, payload_info in self.mutator.mutate(request, self.get_payloads):

            if current_parameter != parameter and not parameter.reversed_parameter:
                # Forget what we know about current parameter
                current_parameter = parameter
                vulnerable_parameter = False
            elif vulnerable_parameter:
                # If parameter is vulnerable, just skip till next parameter
                continue
            if vulnerable_reversed_parameter and parameter.reversed_parameter:
                continue

            if payload_info.type == "time" and request.path_id in self.false_positive_timeouts:
                # If the original request is known to gives timeout and payload is time-based, just skip
                # and move to next payload
                continue

            log_verbose(f"[¨] {mutated_request}")

            try:
                response: Response = await self.crawler.async_send(mutated_request)
            except ReadTimeout:
                # Is the webpage expected to timeout?
                if payload_info.type == "time":
                    # Check for false-positive by asking the original request
                    if await self.does_timeout(request):
                        self.network_errors += 1
                        self.false_positive_timeouts.add(request.path_id)
                        continue

                    vuln_info = "Blind command execution"
                    if parameter.is_qs_injection:
                        vuln_message = Messages.MSG_QS_INJECT.format(vuln_info, page)
                    else:
                        vuln_message = f"{vuln_info} via injection in the parameter {parameter.display_name}"

                    await self.add_critical(
                        request_id=request.path_id,
                        finding_class=CommandExecutionFinding,
                        request=mutated_request,
                        info=vuln_message,
                        parameter=parameter.display_name,
                    )

                    log_red("---")
                    log_red(
                        Messages.MSG_QS_INJECT if parameter.is_qs_injection else Messages.MSG_PARAM_INJECT,
                        vuln_info,
                        page,
                        parameter.display_name
                    )
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")
                    vulnerable_parameter = True
                    continue

                # We didn't expect the webpage to timeout, this is an error
                self.network_errors += 1
                if timeouted:
                    continue

                # Log the request as a new timeout case
                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(mutated_request.http_repr())
                log_orange("---")

                if parameter.is_qs_injection:
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(parameter.display_name)

                await self.add_medium(
                    request_id=request.path_id,
                    finding_class=ResourceConsumptionFinding,
                    request=mutated_request,
                    info=anom_msg,
                    parameter=parameter.display_name,
                )
                timeouted = True
            except RequestError:
                self.network_errors += 1
            else:
                if payload_info.type == "time":
                    continue

                vuln_info = None

                # No timeout raised, check for patterns in response
                if any(rule in response.content for rule in payload_info.rules):
                    vuln_info = payload_info.description
                    # We reached maximum exploitation for this parameter, don't send more payloads
                    vulnerable_parameter = True
                    if parameter.reversed_parameter:
                        vulnerable_reversed_parameter = True
                elif not warned:
                    vuln_info = self._find_warning_in_response(response.content)
                    warned = True

                if vuln_info:
                    # An error message implies that a vulnerability may exist

                    if parameter.is_qs_injection:
                        vuln_message = Messages.MSG_QS_INJECT.format(vuln_info, page)
                        log_message = Messages.MSG_QS_INJECT
                    else:
                        vuln_message = f"{vuln_info} via injection in the parameter {parameter.display_name}"
                        log_message = Messages.MSG_PARAM_INJECT

                    await self.add_critical(
                        request_id=request.path_id,
                        finding_class=CommandExecutionFinding,
                        request=mutated_request,
                        info=vuln_message,
                        parameter=parameter.display_name,
                        response=response
                    )

                    log_red("---")
                    log_red(
                        log_message,
                        vuln_info,
                        page,
                        parameter.display_name
                    )
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")
                elif response.is_server_error and not saw_internal_error:
                    saw_internal_error = True
                    if parameter.is_qs_injection:
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(parameter.display_name)

                    await self.add_high(
                        request_id=request.path_id,
                        finding_class=InternalErrorFinding,
                        request=mutated_request,
                        info=anom_msg,
                        parameter=parameter.display_name,
                    )

                    log_orange("---")
                    log_orange(Messages.MSG_500, page)
                    log_orange(Messages.MSG_EVIL_REQUEST)
                    log_orange(mutated_request.http_repr())
                    log_orange("---")
