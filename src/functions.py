import asyncio
import aiohttp
import concurrent.futures
import hashlib
import jwt
import requests
import urllib.parse
from bs4 import BeautifulSoup
import re

import base64
import sys
import json

#====================================================================================================

async def check_js(js_url):
    output = []

    try:
        if js_url.startswith("//"):
            js_url = "https:" + js_url

        async with aiohttp.ClientSession() as session:
            async with session.get(js_url) as resp:
                response_text = await resp.text()
        # Check for calls to functions that modify the prototype of an object
        prototype_pollution_patterns = [
            (r"Object\.defineProperty", "Object.defineProperty"), 
            (r"Object\.setPrototypeOf", "Object.setPrototypeOf"), 
            (r"Object\.create", "Object.create")
        ]
        for pattern, method in prototype_pollution_patterns:
            if re.search(pattern, response_text):
                output.append(f'prototype pollution {js_url} | {method}')
                return

        # Check for calls to functions that can be used to bypass type checks
        type_check_bypass_patterns = [
            (r"eval", "eval"), 
            (r"Function", "Function"), 
            (r"setTimeout", "setTimeout")
        ]
        for pattern, method in type_check_bypass_patterns:
            if re.search(pattern, response_text):
                output.append(f'type check bypass {js_url} | {method}')
                return

        # Check for calls to functions that can be used to inject malicious code
        malicious_code_injection_patterns = [
            (r"document\.write", "document.write"), 
            (r"innerHTML", "innerHTML")
        ]
        for pattern, method in malicious_code_injection_patterns:
            if re.search(pattern, response_text):
                output.append(f'malicious code injection {js_url} | {method}')
                return

        # Check for calls to functions that can be used to access sensitive information
        sensitive_information_access_patterns = [
            (r"window\.location", "window.location"), 
            (r"document\.cookie", "document.cookie"), 
            (r"localStorage", "localStorage")
        ]
        for pattern, method in sensitive_information_access_patterns:
            if re.search(pattern, response_text):
                output.append(f'sensitive information access {js_url} | {method}')
                return

        # Check for user input being used in a way that may cause code pollution
        user_input_patterns = [
            (r"\.innerHTML\s*=", "innerHTML="),  # Setting innerHTML with user input
            (r"\.outerHTML\s*=", "\.outerHTML\s*="),  # Setting outerHTML with user input
            (r"\.appendChild\(", "appendChild\("),  # Appending user input as a child element
            (r"\.insertBefore\(", "insertBefore\("),  # Inserting user input before an element
            (r"\.replaceChild\(", "replaceChild\("),  # Replacing an element with user input
            (r"\.createElement\(", "createElement\("),  # Creating an element with user input
            (r"\.createTextNode\(", "createTextNode\("),  # Creating a text node with user input
            (r"\.write\(", "write\("),  # Writing user input to the document
            (r"\.execCommand\(", "execCommand(")  # Executing a command with user input
        ]
        for pattern, method in user_input_patterns:
            if re.search(pattern, response_text):
                output.append(f'code pollution {js_url} | {method}')
                return
    except:
        pass
    

async def scan_for_prototype_pollution(url):
    # Send a request to the URL and get the response
    response = requests.get(url)

    output = []

    # Parse the response HTML using BeautifulSoup
    soup = BeautifulSoup(response.text, "html.parser")

    # Find all JavaScript files linked in the HTML
    js_urls = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src and src.endswith(".js"):
            js_urls.append(src)

    # using multii threading await a function
    

    # Check each JavaScript file for prototype pollution
    with concurrent.futures.ThreadPoolExecutor() as executor:
        tasks = []
        for js_url in js_urls:
            future = executor.submit(check_js, js_url)
            tasks.append(await asyncio.wrap_future(future))
        for task in asyncio.as_completed(tasks):
            result = await task
            if result:
                output.extend(result)
    
    return output

async def detect_prototype_pollution(url):
    url = validate_and_fix_url(url)
    # Scan the site for prototype pollution
    await scan_for_prototype_pollution(url)

#====================================================================================================

async def check_hash(stored_hash, line):
    # Hash the line using the same algorithm as the stored hash
    hashed_line = hashlib.sha256(line.strip().encode()).hexdigest()

    # Compare the hashed line to the stored hash
    if hashed_line == stored_hash:
        return line.strip()

async def run_checks(stored_hash):
    # Open the RockYou list and read each line
    with open("rockyou.txt", "r") as f:
        lines = f.readlines()

    # Create a thread pool and submit tasks to check the hashes in parallel
    with concurrent.futures.ThreadPoolExecutor() as executor:
        loop = asyncio.get_event_loop()
        tasks = [loop.run_in_executor(executor, check_hash, stored_hash, line) for line in lines]
        for task in asyncio.as_completed(tasks):
            result = await task
            if result:
                return result
    return None

async def detect_insecure_cryptographic_storage(url):
    # Create a session and send a request to the URL
    session = requests.Session()
    response = session.get(url)

    output = []

    # Check the Authorization header, session, and cookies for JWTs
    jwt_tokens = []
    authorization = response.headers.get("Authorization")
    if authorization and authorization.startswith("Bearer"):
        jwt_tokens.append(authorization[7:])
    for cookie in session.cookies:
        if cookie.name.startswith("jwt"):
            jwt_tokens.append(cookie.value)
    if "jwt" in session.__dict__:
        jwt_tokens.append(session.jwt)

    # Decode and check each JWT for insecure cryptographic storage
    for jwt_token in jwt_tokens:
        try:
            jwt_decoded = jwt.decode(jwt_token, verify=False)
        except jwt.exceptions.DecodeError:
            continue
        result = await run_checks(jwt_decoded)
        if result:
            output.append('insecure jwt')
        else:
            output.append('secure jwt')

    return output

async def check_unsecure_jwt(url):
    # Execute the coroutine and wait for the result
    url = validate_and_fix_url(url)
    result = await detect_insecure_cryptographic_storage(url)

#====================================================================================================

def form_scanner(url):

    url = validate_and_fix_url(url)

    # Send a request to the target URL and get the response
    response = requests.get(url)

    # Parse the response HTML using BeautifulSoup
    soup = BeautifulSoup(response.text, "html.parser")

    # Look for any forms in the HTML
    forms = soup.find_all("form")

    # Print the action and method of each form
    for form in forms:
        print("Form action:", form.get("action"))
        print("Form method:", form.get("method"))

#====================================================================================================

def detect_cors_misconfiguration(url):
    url = validate_and_fix_url(url)
    # Send a request to the target URL with an Origin header set to a different domain
    response = requests.get(url, headers={"Origin": "http://attacker.com"})

    output = []

    # Check the Access-Control-Allow-Origin header in the response
    allow_origin = response.headers.get("Access-Control-Allow-Origin")
    if allow_origin:
        # If the header is present, check if it allows all domains or a specific domain
        output.append(allow_origin)

    return output

#====================================================================================================

def detect_xss(url):
    url = validate_and_fix_url(url)
    # Regular expression to match potential XSS payloads
    xss_regex = r"(<|%3C)([^s]*s)+cript"

    # Send a request to the target URL and get the response
    response = requests.get(url)

    # Search the response text for potential XSS payloads
    matches = re.finditer(xss_regex, response.text)

    output = []

    # Print the line number and payload of each match
    for match in matches:
        start_index = match.start()
        end_index = match.end()

        # Find the start of the line containing the match
        line_start_index = response.text.rfind("\n", 0, start_index) + 1

        # Count the number of newline characters before the start of the line
        line_number = response.text.count("\n", 0, line_start_index) + 1

        payload = response.text[start_index:end_index]

        # Check if the payload is reflected in the response
        reflected_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
        if reflected_payload in response.text:
            output.append("Reflected XSS vulnerability")
        else:
            # If the payload is not reflected, check if the payload is stored in a database
            payload_injection_url = url + "?" + payload
            injection_response = requests.get(payload_injection_url)

            # If the response status code is different after injecting the payload, the vulnerability may be stored XSS
            if injection_response.status_code != response.status_code:
                output.append("Stored XSS vulnerability")
    
    return output

#====================================================================================================

def check_form_security(url):
    url = validate_and_fix_url(url)

    output = []

    # Send a request to the target URL and get the response
    response = requests.get(url)

    # Parse the response HTML using BeautifulSoup
    soup = BeautifulSoup(response.text, "html.parser")

    # Look for any forms in the HTML
    forms = soup.find_all("form")

    # Check the security of each form
    for form in forms:
        action = form.get("action")
        method = form.get("method")

        # Check if the form includes a CSRF token
        csrf_token = form.find("input", {"name": "csrf_token"})
        if csrf_token:
            output.append({
                'action': base64.b64encode(action.encode()).decode('ascii') if action else None,
                'method': base64.b64encode(method.encode()).decode('ascii') if method else None,
                'csrf_token': base64.b64encode(csrf_token["value"].encode()).decode('ascii') if csrf_token["value"] else None,
                'secure': True
            })
        else:
            # If no CSRF token is found, run a simple SQL injection check
            # First, check if the action URL is a relative or absolute URL
            if action != None:
                if action.startswith("http"):
                    inject_test_url = action + "?' or '1'='1"
                else:
                    # If the action URL is relative, prepend the target URL to create a full URL
                    inject_test_url = url + action + "?' or '1'='1"

                inject_test_response = requests.get(inject_test_url)

                # If the response status code is different after injecting the test string, the form may be vulnerable to SQL injection
                if inject_test_response.status_code != response.status_code:
                    output.append({
                        'action': base64.b64encode(action.encode()).decode('ascii') if action else None,
                        'method': base64.b64encode(method.encode()).decode('ascii') if method else None,
                        'secure': False,
                        'sql_injection': True
                    })
                else:
                    output.append({
                        'action': base64.b64encode(action.encode()).decode('ascii') if action else None,
                        'method': base64.b64encode(method.encode()).decode('ascii') if method else None,
                        'secure': True,
                        'sql_injection': False
                    })
    return output

#====================================================================================================

def is_wordpress_site(url):
    url = validate_and_fix_url(url)

    response = requests.get(url)

    if "X-Pingback" in response.headers:
        return True

    if "wp-content" in response.text:
        return True

    uris = ["/wp-admin/","/wp-login.php","/wp-includes/","/wp-content/","/wp-comments-post.php","/wp-admin/admin-ajax.php","/wp-admin/admin-post.php","/wp-cron.php","/wp-json/",]
        
    for uri in uris:
        test_url = url + uri
        response = requests.get(test_url)
            
        if response.status_code == 200:
            return True
            
    return False

#====================================================================================================

def is_shopify_site(url):
    url = validate_and_fix_url(url)

    # Check for presence of specific headers
    headers_to_check = ["x-shopid", "x-shopify-stage"]
    response = requests.get(url)
    for header in headers_to_check:
        if header in response.headers:
            return True

    # Check for presence of "cdn.shopify.com" in the "links" header
    if "links" in response.headers:
        links = response.headers["links"]
        if "https://cdn.shopify.com" in links:
            return True
    
    return False
#====================================================================================================

def detect_platform(target):
    
    if is_wordpress_site(target):
        return "Wordpress"
    elif is_shopify_site(target):
        return "Shopify"
    else:
        url = validate_and_fix_url(target)
        response = requests.get(url)
        if "x-powered-by" in response.headers:
            return requests.get(url).headers["x-powered-by"]


#====================================================================================================

def validate_and_fix_url(url):
    try:
        # Parse the URL and check if it is valid
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError("Invalid URL")
        
        # The URL is valid, so return it
        return url
    
    except ValueError:
        # The URL is invalid, so try to fix it by adding "http://" to the beginning
        fixed_url = "http://" + url
        try:
            # Parse the fixed URL and check if it is valid
            parsed_url = urllib.parse.urlparse(fixed_url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL")
            
            # The fixed URL is valid, so return it
            return fixed_url
        
        except ValueError:
            # The fixed URL is still invalid, so return an error message
            return "Error: Unable to fix invalid URL"


def full_scan(target):


    site = target
    platform = detect_platform(target)
    prototype_pollution = asyncio.run(detect_prototype_pollution(target))
    unsecure_jwt = asyncio.run(check_unsecure_jwt(target))
    xss = detect_xss(target)
    cors = detect_cors_misconfiguration(target)
    form_security = check_form_security(target)
    vulnerabilities = 0

    if prototype_pollution != None:
        for x in prototype_pollution:
            vulnerabilities += 1
    
    if xss != None:
        for x in xss:
            vulnerabilities += 1

    if form_security != None:
        for x in form_security:
            if x['secure'] == False:
                vulnerabilities += 1
    
    if unsecure_jwt:
        vulnerabilities += 1


    print( json.dumps({'site': site,'platform': platform,'prototype_pollution': prototype_pollution,'unsecure_jwt': unsecure_jwt,'xss': xss,'cors': cors,'form_security': form_security,'vulnerabilities': vulnerabilities}))

if __name__ == "__main__":
    target = sys.argv[1]

    # asyncio.run(detect_prototype_pollution(target))
    # asyncio.run(check_unsecure_jwt(target))
    # is_shopify_site(target)
    # is_wordpress_site(target)
    # check_form_security(target)
    # detect_xss(target)
    # detect_cors_misconfiguration(target)
    # form_scanner(target)

    full_scan(target)
