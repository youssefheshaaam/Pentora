# Module Description:
# This module performs directory and file discovery (directory busting/path traversal) by testing for
# the existence of common directories and files on the web server. It helps identify
# hidden or undocumented resources that might contain sensitive information or provide
# additional attack vectors. The module can discover backup files, configuration files,
# admin interfaces, and other potentially valuable resources.
import asyncio
from os.path import join as path_join
from typing import Optional

from httpx import RequestError

from PentoraCore.main.log import log_red, log_verbose
from PentoraCore.attack.attack import Attack
from PentoraCore.net import Request, Response
from PentoraCore.definitions.buster import BusterFinding


class ModuleBuster(Attack):
    """
    Brute force paths on the web-server to discover hidden files and directories.
    """

    PATHS_FILE = "busterPayloads.txt"

    name = "buster"

    do_get = True
    do_post = False

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, crawler_configuration)
        self.known_dirs = []
        self.known_pages = []
        self.new_resources = []
        self.network_errors = 0

    async def check_path(self, url):
        page = Request(url)
        try:
            response = await self.crawler.async_send(page)
        except RequestError:
            self.network_errors += 1
            return False

        if response.redirection_url and response.is_directory_redirection:
            loc = response.redirection_url
            log_red(f"Found webpage {loc}")
            self.new_resources.append(loc)
            await self.add_info(
                finding_class=BusterFinding,
                request=page,
                info=f"Found webpage {loc} on {url}",
            )
        elif (response.redirection_url and not response.is_directory_redirection) \
                or response.status not in [403, 404, 429]:
            log_red(f"Found webpage {page.path}")
            self.new_resources.append(page.path)
            await self.add_info(
                finding_class=BusterFinding,
                request=page,
                info=f"Found webpage {page.path} on {url}",
            )
            return True

        return False

    async def test_directory(self, path: str):
        log_verbose(f"[¨] Testing directory {path}")

        test_page = Request(path + "does_n0t_exist.htm")
        try:
            response = await self.crawler.async_send(test_page)
        except RequestError:
            self.network_errors += 1
            return

        if response.status not in [403, 404]:
            # we don't want to deal with this at the moment
            return

        tasks = set()
        pending_count = 0

        with open(path_join(self.DATA_DIR, self.PATHS_FILE), encoding="utf-8", errors="ignore") as wordlist:
            while True:

                if pending_count < self.options.get("tasks", 5):
                    try:
                        candidate = next(wordlist).strip()
                    except StopIteration:
                        pass
                    else:
                        url = path + candidate
                        if url not in self.known_dirs and url not in self.known_pages and url not in self.new_resources:
                            task = asyncio.create_task(self.check_path(url))
                            tasks.add(task)

                if not tasks:
                    break

                done_tasks, pending_tasks = await asyncio.wait(
                    tasks,
                    timeout=0.01,
                    return_when=asyncio.FIRST_COMPLETED
                )
                pending_count = len(pending_tasks)
                for task in done_tasks:
                    try:
                        await task
                    except RequestError:
                        self.network_errors += 1
                    tasks.remove(task)

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        if not self.do_get:
            return

        # First we make a list of unique webdirs and webpages without parameters
        async for scanned_request, __ in self.persister.get_links(attack_module=self.name):
            path = scanned_request.path
            if path.endswith("/"):
                if path not in self.known_dirs:
                    self.known_dirs.append(path)
            else:
                if path not in self.known_pages:
                    self.known_pages.append(path)

        # Then for each known webdirs we look for unknown webpages inside
        for current_dir in self.known_dirs:
            await self.test_directory(current_dir)

        # Finally, for each discovered webdirs we look for more webpages
        while self.new_resources:
            current_res = self.new_resources.pop(0)
            if current_res.endswith("/"):
                # Mark as known then explore
                self.known_dirs.append(current_res)
                await self.test_directory(current_res)
            else:
                self.known_pages.append(current_res)
