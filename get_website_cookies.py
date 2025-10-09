from selenium import webdriver  # type: ignore
from selenium.webdriver.chrome.service import Service  # type: ignore
from selenium.webdriver.chrome.options import Options  # type: ignore
from webdriver_manager.chrome import ChromeDriverManager  # type: ignore
import json
import time

def get_all_browser_cookies(url):
    # Set up Chrome options
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")  # Headless mode
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--remote-debugging-port=9222")  # enable CDP

    # Launch Chrome browser
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

    # Visit target site
    driver.get(url)
    time.sleep(3)  # wait for all cookies (including JS/async) to load

    # === Fetch all browser cookies via Chrome DevTools Protocol ===
    all_cookies = driver.execute_cdp_cmd("Network.getAllCookies", {})

    # Extract cookie list
    cookies_list = all_cookies.get("cookies", [])

    # Print formatted JSON
    print(f"\n=== All Browser Cookies for {url} ===")
    print(json.dumps(cookies_list, indent=2))

    # Optional: print total count
    print(f"\nTotal cookies retrieved: {len(cookies_list)}")

    # Close the browser
    driver.quit()

if __name__ == "__main__":
    site = input("Enter the website URL (e.g., https://example.com): ").strip()
    get_all_browser_cookies(site)


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
