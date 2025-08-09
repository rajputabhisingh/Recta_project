import schedule
import time
import logging
import os
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Create screenshot directory
screenshot_dir = "screenshots"
os.makedirs(screenshot_dir, exist_ok=True)

# Create dynamic log file with timestamp
log_timestamp = datetime.now().strftime("%Y%m%d_%H%M")
log_filename = f"login_logs_{log_timestamp}.txt"

# Logger setup
logging.basicConfig(
    filename=log_filename,
    filemode="a",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log(message, level="info"):
    print(message)
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)

def take_screenshot(driver, site_name):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(screenshot_dir, f"screenshot_{site_name}_{timestamp}.png")
    try:
        driver.save_screenshot(filename)
        log(f"📸 Screenshot saved: {filename}", "info")
    except Exception as e:
        log(f"⚠️ Failed to take screenshot for {site_name}: {e}", "warning")

def process_sites(credentials):
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--window-size=1920,1080')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--no-sandbox')

    try:
        driver = webdriver.Chrome(service=Service(), options=chrome_options)
        log("🔧 Headless browser launched", "info")
    except Exception as e:
        log(f"❌ Failed to launch browser: {e}", "error")
        return

    urls = [
        "https://www.amazon.in/",
        "https://accounts.google.com/signin",
        "https://wns-etraveligroupoutsourcing.talentlms.com/index"
    ]

    try:
        driver.get(urls[0])
        for _ in urls[1:]:
            driver.execute_script("window.open('');")

        tabs = driver.window_handles
        wait = WebDriverWait(driver, 15)

        for i, url in enumerate(urls):
            site_name = url.split("//")[1].split("/")[0].replace('.', '_')

            try:
                driver.switch_to.window(tabs[i])
                driver.get(url)
                time.sleep(2)

                if "amazon" in url:
                    try:
                        sign_in_button = wait.until(EC.element_to_be_clickable((By.ID, "nav-link-accountList")))
                        sign_in_button.click()

                        email_input = wait.until(EC.presence_of_element_located((By.ID, "ap_email")))
                        email_input.send_keys(credentials['Email'])

                        continue_btn = wait.until(EC.element_to_be_clickable((By.ID, "continue")))
                        continue_btn.click()

                        password_input = wait.until(EC.presence_of_element_located((By.ID, "ap_password")))
                        password_input.send_keys(credentials['Password'])

                        sign_in_submit = wait.until(EC.element_to_be_clickable((By.ID, "signInSubmit")))
                        sign_in_submit.click()

                        log(f"✅ Amazon login successful for {credentials['Email']}", "info")
                    except Exception as e:
                        log(f"⚠️ Amazon login failed: {e}", "warning")

                    take_screenshot(driver, site_name)

                elif "accounts.google.com" in url:
                    try:
                        email_input = wait.until(EC.presence_of_element_located((By.ID, "identifierId")))
                        email_input.send_keys(credentials['Email'])

                        next_btn = wait.until(EC.element_to_be_clickable((By.ID, "identifierNext")))
                        next_btn.click()

                        password_input = wait.until(EC.presence_of_element_located((By.NAME, "password")))
                        password_input.send_keys(credentials['Password'])

                        pass_next = wait.until(EC.element_to_be_clickable((By.ID, "passwordNext")))
                        pass_next.click()

                        log(f"✅ Gmail login successful for {credentials['Email']}", "info")
                    except Exception as e:
                        log(f"⚠️ Gmail login failed: {e}", "warning")

                    take_screenshot(driver, site_name)

                elif "talentlms.com" in url:
                    try:
                        username_input = wait.until(EC.presence_of_element_located((By.ID, "login")))
                        username_input.send_keys(credentials['Email'])

                        password_input = wait.until(EC.presence_of_element_located((By.ID, "password")))
                        password_input.send_keys(credentials['Password'])

                        login_button = wait.until(EC.element_to_be_clickable((By.NAME, "submit")))
                        login_button.click()

                        # ✅ Wait for post-login dashboard/header
                        try:
                            wait.until(EC.presence_of_element_located((By.ID, "header")))
                        except:
                            time.sleep(3)  # fallback if selector not found

                        log(f"✅ TalentLMS login successful for {credentials['Email']}", "info")
                    except Exception as e:
                        log(f"⚠️ TalentLMS login failed: {e}", "warning")

                    take_screenshot(driver, site_name)

            except Exception as e:
                log(f"⚠️ Error processing site {url}: {e}", "warning")
                take_screenshot(driver, site_name + "_error")

    except Exception as e:
        log(f"❌ General processing error: {e}", "error")
    finally:
        driver.quit()
        log("🧹 Browser closed", "info")

# Static credentials
user1_credentials = {
    'Email': 'u424221@wns.com',
    'Password': 'Sabre@963852741'
}

user2_credentials = {
    'Email': 'sambhusinghbalwan786@gmail.com',
    'Password': 'Sambhu@7865'
}

user3_credentials = {
    'Email': 'user3@example.com',
    'Password': 'User3@789'
}

# Schedule handlers
def run_user1():
    log(f"📌 Running User 1 scheduler at {datetime.now()}", "info")
    process_sites(user1_credentials)

def run_user2():
    log(f"📌 Running User 2 scheduler at {datetime.now()}", "info")
    process_sites(user2_credentials)

def run_user3():
    log(f"📌 Running User 3 scheduler at {datetime.now()}", "info")
    process_sites(user3_credentials)

# Schedule jobs (adjust times as needed)
schedule.every().day.at("13:35").do(run_user1)
schedule.every().day.at("13:38").do(run_user2)
schedule.every().day.at("13:40").do(run_user3)

log("🔁 Scheduler started. Waiting for scheduled jobs...", "info")

try:
    while True:
        schedule.run_pending()
        time.sleep(1)
except KeyboardInterrupt:
    log("⛔ Scheduler stopped manually.", "warning")
