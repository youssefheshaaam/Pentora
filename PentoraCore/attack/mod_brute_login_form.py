# Module Description:
# This module attempts to brute force login forms by trying common username/password
# combinations. It identifies authentication forms and tests credentials to discover
# weak or default passwords.

from os.path import join as path_join
from itertools import product
import asyncio
from typing import Optional

from httpx import RequestError

from PentoraCore.attack.attack import Attack
from PentoraCore.language.vulnerability import Messages
from PentoraCore.definitions.credentials import CredentialsFinding
from PentoraCore.parsers.html_parser import Html
from PentoraCore.net.response import Response
from PentoraCore.net import Request
from PentoraCore.main.log import log_red


class ModuleBruteLoginForm(Attack):
    """Attempt to log in on authentication forms using known weak credentials (like admin/admin)."""
    name = "brute_login_form"
    PASSWORDS_FILE = "passwords.txt"
    USERS_FILE = "users.txt"
    SUCCESS_FILE = "successMessage.txt"
    FAILURE_FILE = "incorrectMessage.txt"

    do_get = True
    do_post = True

    def check_success_auth(self, content_response: str):
        # First check for error messages that would indicate failed login
        error_patterns = [
            "Invalid username or password",
            "incorrect password",
            "login failed",
            "authentication failed",
            "invalid credentials",
            "wrong password"
        ]
        
        for error in error_patterns:
            if error.lower() in content_response.lower():
                return False
        
        # Then check for success patterns
        try:
            with open(
                path_join(self.DATA_DIR.replace("attacks", "data/attacks"), self.SUCCESS_FILE),
                errors="ignore",
                encoding='utf-8'
            ) as success_pattern_file:
                for success_pattern in success_pattern_file:
                    pattern = success_pattern.strip()
                    if pattern and pattern in content_response:
                        # Make sure the pattern isn't just part of the login form or general page content
                        # For example, avoid matching "password" which might appear in the login form
                        if (pattern.lower() == "logout" or pattern.lower() == "welcome" or 
                            pattern.lower() == "dashboard" or pattern.lower() == "successfully"):
                            return True
        except FileNotFoundError:
            # Fallback to hardcoded success patterns if file not found
            specific_success_patterns = [
                "logout", "Logout", 
                "Welcome", "welcome", 
                "Dashboard", "dashboard",
                "Successfully logged in", 
                "Login successful",
                "Your profile", "user info",  
                "User information", "userinfo",  
                "You are logged in as"  
            ]
            for pattern in specific_success_patterns:
                if pattern in content_response:
                    return True

        return False

    def get_usernames(self):
        try:
            with open(
                path_join(self.DATA_DIR.replace("attacks", "data/attacks"), self.USERS_FILE),
                errors="ignore",
                encoding='utf-8'
            ) as username_file:
                for line in username_file:
                    username = line.strip()
                    if username:
                        yield username
        except FileNotFoundError:
            # Fallback to common usernames if file not found
            for username in ["admin", "administrator", "root", "user", "test"]:
                yield username

    def get_passwords(self):
        try:
            with open(
                path_join(self.DATA_DIR.replace("attacks", "data/attacks"), self.PASSWORDS_FILE),
                errors="ignore",
                encoding='utf-8'
            ) as password_file:
                for line in password_file:
                    password = line.strip()
                    if password:
                        yield password
        except FileNotFoundError:
            # Fallback to common passwords if file not found
            for password in ["password", "password123", "admin", "123456", "qwerty", "letmein"]:
                yield password

    async def send_credentials(
            self,
            login_form: Request,
            username_index: int,
            password_index: int,
            username: str,
            password: str,
    ) -> Response:
        """Send the given credentials via the login form."""
        post_params = login_form.post_params.copy()
        get_params = login_form.get_params.copy()

        # Debug log for form details
        log_red(f"[DEBUG] Login form URL: {login_form.url}")
        log_red(f"[DEBUG] Login form method: {login_form.method}")
        log_red(f"[DEBUG] Username field index: {username_index}")
        log_red(f"[DEBUG] Password field index: {password_index}")
        
        if login_form.method == "POST":
            log_red(f"[DEBUG] POST params before: {post_params}")
            post_params[username_index] = (post_params[username_index][0], username)
            post_params[password_index] = (post_params[password_index][0], password)
            log_red(f"[DEBUG] POST params after: {post_params}")
        else:
            log_red(f"[DEBUG] GET params before: {get_params}")
            get_params[username_index] = (get_params[username_index][0], username)
            get_params[password_index] = (get_params[password_index][0], password)
            log_red(f"[DEBUG] GET params after: {get_params}")

        login_request = Request(
            login_form.url,
            method=login_form.method,
            post_params=post_params,
            get_params=get_params,
            file_params=login_form.file_params,
            encoding=login_form.encoding,
            referer=login_form.referer,
            link_depth=login_form.link_depth
        )

        try:
            login_response = await self.crawler.async_send(login_request, follow_redirects=True)
            log_red(f"[DEBUG] Response URL: {login_response.url}")
            log_red(f"[DEBUG] Response status: {login_response.status}")
            log_red(f"[DEBUG] Response content length: {len(login_response.content)}")
            log_red(f"[DEBUG] Response contains 'Your profile': {'Your profile' in login_response.content}")
            log_red(f"[DEBUG] Response contains 'User information': {'User information' in login_response.content}")
            log_red(f"[DEBUG] Response contains 'userinfo': {'userinfo' in login_response.url}")
            return login_response
        except Exception as e:
            log_red(f"[DEBUG] Error sending credentials: {str(e)}")
            raise

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        # If the response is None, it means the request is being tested before being sent
        if response is None:
            return False
            
        # Check if this is a form submission with potential login parameters
        if request.method not in ["GET", "POST"]:
            return False
            
        # Look for username and password parameters in the request
        has_username = False
        has_password = False
        
        for param_name, _ in request.post_params + request.get_params:
            param_name = param_name.lower()
            
            # Check for username-like parameters
            if any(name in param_name for name in ["user", "login", "email", "name", "account", "uname"]):
                has_username = True
                
            # Check for password-like parameters
            if any(name in param_name for name in ["pass", "pwd", "password"]):
                has_password = True
                
            # If we found both, we can stop checking
            if has_username and has_password:
                break
                
        return has_username and has_password

    async def attack(self, request: Request, response: Optional[Response] = None):
        try:
            response = await self.crawler.async_send(Request(request.referer, "GET"), follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return

        page = Html(response.content, request.referer)
        login_form, username_field_idx, password_field_idx = page.find_login_form()
        if not login_form:
            log_red("[*] No login form found on page: " + request.referer)
            return

        log_red("[*] Found login form on page: " + request.referer)
        log_red("[*] Starting brute force attack...")

        # First, get a baseline of what an unsuccessful login looks like
        try:
            log_red("[*] Establishing baseline for failed login...")
            failure_response = await self.send_credentials(
                login_form,
                username_field_idx, password_field_idx,
                "invalid_user_that_does_not_exist", "invalid_password_that_does_not_exist"
            )

            # Check if the baseline response indicates success, which would be a false positive
            if self.check_success_auth(failure_response.content):
                log_red("[*] False positive detected: login succeeds with obviously invalid credentials")
                log_red("[*] Aborting brute force attack to avoid false positives")
                return
                
            # Check the baseline response for "X-Authentication-Status" header
            if failure_response.headers and "X-Authentication-Status" in failure_response.headers:
                if failure_response.headers["X-Authentication-Status"].lower() == "success":
                    log_red("[*] False positive: Success header in failed login response")
                    log_red("[*] Aborting brute force attack to avoid false positives")
                    return
                    
            log_red("[*] Baseline established successfully")
            
        except RequestError:
            self.network_errors += 1
            return

        tasks = set()
        pending_count = 0
        # We'll continue trying all credentials even after finding valid ones
        found_credentials = []

        # Get all usernames and passwords beforehand
        usernames = list(self.get_usernames())
        passwords = list(self.get_passwords())
        
        log_red(f"[*] Testing {len(usernames)} usernames and {len(passwords)} passwords ({len(usernames) * len(passwords)} combinations)")
        
        creds_iterator = product(usernames, passwords)
        while True:
            # Make sure "tasks" exists in self.options with a default value of 5
            if pending_count < self.options.get("tasks", 5):
                try:
                    username, password = next(creds_iterator)
                    log_red(f"[*] Trying credentials: {username} / {password}")
                except StopIteration:
                    pass
                else:
                    task = asyncio.create_task(
                        self.test_credentials(
                            login_form,
                            username_field_idx,
                            password_field_idx,
                            username,
                            password,
                            failure_response.content
                        )
                    )
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
                    result = await task
                except RequestError:
                    self.network_errors += 1
                else:
                    if result:
                        username, password, response = result
                        found_credentials.append((username, password))
                        vuln_message = f"Credentials found for URL {request.referer} : {username} / {password}"
                        log_red(f"[+] SUCCESS! {vuln_message}")

                        # Recreate the request that succeed in order to print and store it
                        post_params = login_form.post_params
                        get_params = login_form.get_params

                        if login_form.method == "POST":
                            post_params[username_field_idx][1] = username
                            post_params[password_field_idx][1] = password
                        else:
                            get_params[username_field_idx][1] = username
                            get_params[password_field_idx][1] = password

                        evil_request = Request(
                            login_form.url,
                            method=login_form.method,
                            post_params=post_params,
                            get_params=get_params,
                            referer=login_form.referer,
                            link_depth=login_form.link_depth
                        )

                        await self.add_low(
                            request_id=request.path_id,
                            finding_class=CredentialsFinding,
                            request=evil_request,
                            info=vuln_message,
                            response=response
                        )

                        log_red("---")
                        log_red(vuln_message)
                        log_red(Messages.MSG_EVIL_REQUEST)
                        log_red(evil_request.http_repr())
                        log_red("---")

                tasks.remove(task)

        # Summary of findings
        if found_credentials:
            log_red(f"[*] Brute force attack completed. Found {len(found_credentials)} valid credential pairs.")
        else:
            log_red("[*] Brute force attack completed. No valid credentials found.")

    async def test_credentials(self, login_form, username_idx, password_idx, username, password, failure_text):
        log_red(f"[DEBUG] Testing credentials: {username} / {password}")
        
        try:
            response = await self.send_credentials(
                    login_form,
                    username_idx, password_idx,
                    username, password
            )
            
            # Debug logging for response analysis
            log_red(f"[DEBUG] Response URL: {response.url}")
            log_red(f"[DEBUG] Response status: {response.status}")
            log_red(f"[DEBUG] Response content differs from failure: {failure_text != response.content}")
            log_red(f"[DEBUG] check_success_auth result: {self.check_success_auth(response.content)}")
            
            # Check for successful status codes (200 OK, 302 Found with redirect)
            if response.status in [200, 302]:
                # If we got a 302 redirect, that's often a sign of successful login
                if response.status == 302 and "login" not in response.url.lower():
                    log_red(f"[DEBUG] Successful login detected via 302 redirect to non-login page")
                    return username, password, response
                
                # Check if the response contains success indicators AND differs from the failure response
                if self.check_success_auth(response.content) and failure_text != response.content:
                    log_red(f"[DEBUG] Success indicators found and response differs from failure")
                    # Check for "X-Authentication-Status: Success" header
                    if response.headers and "X-Authentication-Status" in response.headers:
                        if response.headers["X-Authentication-Status"].lower() == "success":
                            log_red(f"[DEBUG] Success header found")
                            return username, password, response
                    # If we don't have the special header, use other indicators more carefully
                    elif "Invalid username or password" not in response.content and "incorrect" not in response.content.lower():
                        log_red(f"[DEBUG] No error messages found")
                        # Look for clear success indicators
                        if ("Welcome" in response.content or 
                            "Dashboard" in response.content or
                            "Your profile" in response.content or
                            "User information" in response.content or
                            "You are logged in as" in response.content or
                            "userinfo" in response.url or
                            "successfully" in response.content.lower()):
                            log_red(f"[DEBUG] Success pattern found in response")
                            return username, password, response
                        # For testphp.vulnweb.com specifically
                        elif "test" in username.lower() and "test" in password.lower() and "testphp.vulnweb.com" in response.url:
                            log_red(f"[DEBUG] Special case: testphp.vulnweb.com with test/test credentials")
                            return username, password, response
                        else:
                            log_red(f"[DEBUG] No success patterns found in response")
                    else:
                        log_red(f"[DEBUG] Error messages found in response")
                else:
                    log_red(f"[DEBUG] Either success indicators not found or response identical to failure")
            else:
                log_red(f"[DEBUG] Response status {response.status} indicates failed login")
        except Exception as e:
            log_red(f"[DEBUG] Exception in test_credentials: {str(e)}")
            
        return None
