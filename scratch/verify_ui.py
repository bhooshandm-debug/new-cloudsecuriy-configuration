import urllib.request
import urllib.parse
import http.cookiejar

cookie_jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

base_url = "http://127.0.0.1:5000"

def check(url, expect_code=200):
    try:
        resp = opener.open(base_url + url)
        print(f"GET {url} -> {resp.getcode()} (length: {len(resp.read())})")
    except urllib.error.HTTPError as e:
        print(f"GET {url} -> HTTPError {e.code}")

print("Testing unauthenticated pages:")
check("/login")
check("/register")
check("/forgot-password")

# Let's check login flow
print("\nFetching login CSRF token...")
resp = opener.open(base_url + "/login")
html = resp.read().decode('utf-8')
import re
match = re.search(r'name="csrf_token" value="([^"]+)"', html)
if match:
    csrf = match.group(1)
    print("Found CSRF token:", csrf[:10] + "...")
    # Attempt login with existing user
    login_data = urllib.parse.urlencode({
        "csrf_token": csrf,
        "identifier": "Bhooshan",
        "password": "Password123!"  # or similar
    }).encode('utf-8')
    try:
        req = urllib.request.Request(base_url + "/login", data=login_data, method="POST")
        resp = opener.open(req)
        print(f"POST /login -> {resp.getcode()} (redirected to {resp.geturl()})")
        
        # Test authenticated views
        print("\nTesting authenticated views:")
        for path in ["/", "/accounts/", "/scans/", "/findings/", "/scans/compare", "/assistant/", "/reports/"]:
            check(path)
    except urllib.error.HTTPError as e:
        print("Login attempt response:", e.code)
else:
    print("Could not find CSRF token in /login")
