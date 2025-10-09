import pychrome, json, time, subprocess, contextlib # type: ignore

subprocess.Popen([
    "google-chrome",
    "--remote-debugging-port=9222",
    "--user-data-dir=/tmp/chrome-profile",
    "--headless",
    "--disable-gpu",
    "--no-sandbox",
    "--ignore-certificate-errors",
    "--allow-insecure-localhost",
    "--disable-logging",
    "--log-level=3"
])
time.sleep(2)

def get_all_cookies(url):
    browser = pychrome.Browser(url="http://127.0.0.1:9222")
    tab = browser.new_tab()
    tab.start()
    tab.call_method("Network.enable")
    tab.call_method("Page.navigate", url=url)

    time.sleep(5)

    cookies = tab.call_method("Network.getAllCookies")

    print(f"\n=== All Browser Cookies for {url} ===")
    print(json.dumps(cookies["cookies"], indent=2))
    print(f"\nTotal cookies retrieved: {len(cookies['cookies'])}")

    time.sleep(1)
    with contextlib.suppress(Exception):
        tab.stop()
        browser.close_tab(tab)

if __name__ == "__main__":
    site = input("Enter the website URL (e.g., https://example.com): ").strip()
    get_all_cookies(site)


# ✅ Example (with requests) without selenium and playwright
# import requests
# import json

# url = input("Enter website URL (e.g., https://example.com): ").strip()

# session = requests.Session()
# response = session.get(url)

# cookies_list = []
# for cookie in session.cookies:
#     cookies_list.append({
#         "name": cookie.name,
#         "value": cookie.value,
#         "domain": cookie.domain,
#         "path": cookie.path,
#         "expires": cookie.expires,
#         "secure": cookie.secure,
#     })

# print(f"\n=== Cookies from {url} ===")
# print(json.dumps(cookies_list, indent=2))


# Example (including JS-set cookies) without selenium and playwright
# import sqlite3
# import os
# import json
# from urllib.parse import urlparse

# url = input("Enter the website URL (e.g., https://example.com): ").strip()
# parsed_url = urlparse(url)
# domain = parsed_url.netloc

# if domain.startswith("www."):
#     domain = domain[4:]  # remove www. for matching

# chrome_path = os.path.expanduser("~/.config/google-chrome/Default/Cookies")

# if not os.path.exists(chrome_path):
#     raise FileNotFoundError("Couldn't find Chrome cookies DB. Adjust the path if necessary.")

# conn = sqlite3.connect(chrome_path)
# cursor = conn.cursor()

# query = """
# SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly 
# FROM cookies
# WHERE host_key LIKE ?
# """
# cursor.execute(query, (f"%{domain}%",))
# rows = cursor.fetchall()

# cookies = []
# for r in rows:
#     cookies.append({
#         "domain": r[0],
#         "name": r[1],
#         "value": r[2],
#         "path": r[3],
#         "expires": r[4],
#         "secure": bool(r[5]),
#         "httpOnly": bool(r[6])
#     })

# conn.close()

# print(f"\n=== Cookies stored in Chrome for {domain} ===")
# print(json.dumps(cookies, indent=2))


# To check whether cookies are present in chrome of not
# import sqlite3, os
# for p in ["Default", "Profile 1", "Profile 2"]:
#     path = os.path.expanduser(f"~/.config/google-chrome/{p}/Cookies")
#     if os.path.exists(path):
#         print(f"\n>>> Checking {p}")
#         conn = sqlite3.connect(path)
#         cursor = conn.cursor()
#         cursor.execute("SELECT DISTINCT host_key FROM cookies LIMIT 20")
#         print([r[0] for r in cursor.fetchall()])
#         conn.close()
