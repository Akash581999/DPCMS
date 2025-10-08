from selenium import webdriver # type: ignore
from selenium.webdriver.chrome.service import Service # type: ignore
from selenium.webdriver.chrome.options import Options # type: ignore
from webdriver_manager.chrome import ChromeDriverManager # type: ignore
import json
import time

def get_cookies_from_site(url):
    # Set up Chrome options
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run Chrome without UI
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")

    # Launch Chrome
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

    # Visit the target website
    driver.get(url)

    # Wait a few seconds for all cookies to load
    time.sleep(3)

    # Fetch cookies visible to JavaScript (session + persistent)
    cookies = driver.get_cookies()

    # Print cookies in terminal
    print(f"\n=== Cookies for {url} ===")
    print(json.dumps(cookies, indent=2))

    # Close browser
    driver.quit()

if __name__ == "__main__":
    site = input("Enter the website URL (e.g., https://example.com): ").strip()
    get_cookies_from_site(site)
