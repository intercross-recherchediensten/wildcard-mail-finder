from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains
from bs4 import BeautifulSoup
from os import system, name, path
from collections import Counter

import requests
import re
import csv
import json
import time
import hashlib
import os
# import netlas

# GENERAL FUNCTIONS*******************************************************************************************************

def clearscreen():
    # Clears the console screen. Uses 'cls' for Windows and 'clear' for Linux/OS X.
    if name == "nt":
        system("cls")
    else:
        system("clear")

def ascii_art():
    # Displays ASCII art from a file.
    with open("ascii-art-wef.txt", "r") as file:
        print(file.read())
    print("")

def start_questions():
    # Asks the user to enter a wildcard email address.
    clearscreen()
    ascii_art()
    return input("Enter a wildcard email address (e.g., zho***@163.com): ")

def md5_hash(email):
    # Converts an email address to its MD5 hash.
    return hashlib.md5(email.encode()).hexdigest()

# MODULE INTELX / PHONEBOOK***********************************************************************************************

def info_login_intelx():
    # Informs the user about logging into Intelx.io.
    clearscreen()
    ascii_art()
    print("\nNOTE: You will be redirected to the login page of https://intelx.io/login. Log in and solve the captcha. Do not close the browser after logging in. Return to this script and press Enter to restart the tool...")
    input("\nPress Enter now ")

def login_intelx(driver):
    # Logs into intelx.io and waits for a successful login.
    driver.get("https://intelx.io/login")
    while "logout" not in driver.page_source.lower():
        time.sleep(1)  # Poll every second until "logout" is found in the page source

def show_login_success_popup(driver):
    # Shows a popup after successful login.
    js_script = """
    var div = document.createElement('div');
    div.innerHTML = '<strong>Login successful!</strong><br>Do NOT close the browser, but return immediately to the command line tool. This message will close automatically in 10 seconds.';
    div.style.position = 'fixed';
    div.style.left = '50%';
    div.style.top = '50%';
    div.style.transform = 'translate(-50%, -50%)';
    div.style.backgroundColor = '#f8d7da';
    div.style.color = '#721c24';
    div.style.border = '2px solid #f5c6cb';
    div.style.padding = '20px';
    div.style.zIndex = '1000';
    div.style.width = '500px';
    div.style.height = '400px';
    div.style.display = 'flex';
    div.style.justifyContent = 'center';
    div.style.alignItems = 'center';
    div.style.textAlign = 'center';
    div.style.fontSize = '16px';
    div.style.boxShadow = '0 4px 8px rgba(0,0,0,0.1)';
    div.style.zIndex = '1000';
    document.body.appendChild(div);
    setTimeout(function() { document.body.removeChild(div); }, 10000);
    """
    driver.execute_script(js_script)
    time.sleep(5)  # Wait 15 seconds for the pop-up to close automatically

def restart_na_login_intelx():
    # Asks the user to press Enter after logging into Intelx.io.
    clearscreen()
    ascii_art()
    input("\n\nAlready logged into Intelx.io? \n\nThen press Enter to continue...")

def get_emails_phonebook(driver, email_domain, start_address, email_regex):
    # Retrieves emails from phonebook.cz using Intelx.io SSO.
    # Navigate to the SSO page to synchronize login status with phonebook.cz
    driver.get("https://intelx.io/sso?a=phonebook")
    time.sleep(3)  # Wait a bit to complete the SSO action

    # Now navigate to phonebook.cz
    driver.get("https://phonebook.cz/")
    time.sleep(4)  # Wait a bit for the page to load and for the user to verify they are logged in

    # Retrieve the page source and look for API_URL and API_KEY
    driver.get("https://phonebook.cz/js/config.js")
    time.sleep(5)  # Wait a bit for the page to load
    page_source = driver.page_source

    api_url_match = re.search(r"var API_URL = '([^']+)'", page_source)
    api_key_match = re.search(r"var API_KEY = '([^']+)'", page_source)

    if api_url_match and api_key_match:
        api_url = api_url_match.group(1)
        api_key = api_key_match.group(1)
        print(f"API_URL: {api_url}")
        print(f"API_KEY: {api_key}")
    else:
        print("Could not find API_URL and/or API_KEY in the page source.")
        driver.quit()
        return

    # Perform the POST request to obtain the ID (as done previously)
    # Perform the POST request with JavaScript and save the response in window.responseData
    post_data = json.dumps({"term": email_domain, "maxresults": 10000, "media": 0, "target": 2, "terminate": [None], "timeout": 20})
    js_script = f"""
    fetch("{api_url}phonebook/search?k={api_key}", {{
        method: "POST",
        headers: {{
            "Content-Type": "application/json"
        }},
        body: '{post_data}'
    }})
    .then(response => response.json())
    .then(data => {{
        console.log(data);
        window.responseData = data; // Save the data in the window object
    }})
    .catch(error => console.error('Error:', error));
    """ 
    driver.execute_script(js_script)
    time.sleep(3)  # Wait a bit for the POST request to complete

    # Read the saved response and print the ID
    response_data = driver.execute_script("return window.responseData;")
    if response_data:
        #print("Response data:", response_data)
        search_id = response_data.get("id")
        print(f"Obtained ID: {search_id}")
    else:
        print("Could not capture the response data.")

    all_emails = []
    new_emails_found = True
    while new_emails_found:
        get_url = f"{api_url}phonebook/search/result?k={api_key}&id={search_id}&limit=10000"
        driver.get(get_url)
        time.sleep(7)  # Wait a bit for the GET request to complete and the data to load

        # Here you need to extract the data from the page. This can be complex because the data may be loaded in JavaScript.
        # Example: extracting the JSON data from the page
        page_source = driver.page_source
        email_matches = re.findall(r'"selectorvalue":"([^"]+)"', page_source)
        if email_matches:
            new_batch = [email for email in email_matches if email not in all_emails]
            if new_batch:
                all_emails.extend(new_batch)
                print(f"New emails found: {len(new_batch)}")
            else:
                new_emails_found = False
        else:
            new_emails_found = False

    filtered_emails = [email for email in all_emails if email_regex.match(email) and email.startswith(start_address) and email.endswith(email_domain)]
    print(f"After filtering, total {len(filtered_emails)} emails found matching the pattern")

    return filtered_emails

# MODULE VIEWDNS***********************************************************************************************************

def extract_domains_from_html(html):
    # Extracts domain names from HTML content.# 
    return re.findall(r'<tr><td>([^<]+)</td>', html)[1:]

def get_domains_viewdns(driver, user_email):
    # Retrieves domain names associated with a given email address from viewdns.info.
    viewdns_url = f'https://viewdns.info/reversewhois/?q={user_email.replace("@", "%40")}'
    driver.get(viewdns_url)
    time.sleep(2)
    viewdns_html = driver.page_source
    domain_names = extract_domains_from_html(viewdns_html)
    return domain_names

# MODULE WHOISHISTORY*****************************************************************************************************

def query_whois_os_ai(domain):
    # Queries domain history from whois.os.ai.
    url = "https://whois.os.ai/get_domain_history"
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "X-Requested-With": "XMLHttpRequest"}
    response = requests.post(url, headers=headers, data={"domain": domain})
    return json.loads(response.text).get(domain, []) if response.status_code == 200 else []

def extract_emails_from_whois_data(whois_data, email_pattern):
    # Extracts emails from WHOIS data.
    emails = []
    for entry in whois_data:
        email = entry.get('registrant_email')
        if email and re.match(email_pattern, email):
            emails.append(email)
    return emails

# Function to fetch HTML of a page with error handling
def get_html_from_url_chinaz(url, driver, first_query=True):
    # Fetches HTML content from a URL using Chinaz with error handling.
    wait_time = 12 if first_query else 5
    max_attempts = 3
    for attempt in range(max_attempts):
        driver.get(url)
        time.sleep(wait_time)  # Wait 10 or 5 seconds

        # Check for "Nothing found" error message
        try:
            if WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.ID, "info"))
            ).text == "Nothing found. Please try another one.":
                return ""  # No results, move on to the next domain name
        except:
            pass  # Continue if "Nothing found" is not found

        # Check for "An exception occurred" error message
        try:
            error_elements = WebDriverWait(driver, 10).until(
                EC.presence_of_all_elements_located((By.CSS_SELECTOR, ".tool-default-page"))
            )
            for element in error_elements:
                if "exception" in element.text.lower():
                    time.sleep(5)  # Wait and try again
                    continue
        except:
            pass  # Continue if "An exception occurred" is not found

        # No error messages, return the HTML
        return driver.page_source

    return ""  # Return empty string if all attempts fail

def extract_emails_chinaz(html, email_pattern):
    # Extracts emails from HTML content using Chinaz.
    return re.findall(email_pattern, html)

# MODULE CRT.SH*********************************************************************************************************** 

def query_crt_sh(email_domain, email_pattern):
    # Queries crt.sh for certificates related to an email domain.
    query_url = f"https://crt.sh/?q=%40{email_domain}"
    response = requests.get(query_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    results = []

    for row in soup.find_all('tr')[1:]:  # Skip header row
        cols = row.find_all('td')
        if len(cols) >= 6:
            common_name = cols[4].get_text(strip=True)
            email = cols[5].get_text(strip=True)
            if re.match(email_pattern, email):
                results.append((query_url, common_name, email))
    return results

# MODULE SKYMEM***********************************************************************************************************

def get_emails_from_html_skymem(html, start_address, email_domain):
    # Extracts emails from HTML content using Skymem.
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    found_emails = email_pattern.findall(html)
    filtered_emails = [email for email in found_emails if email.startswith(start_address) and email.endswith(email_domain)]
    return filtered_emails

def query_skymem(start_address, email_domain):
    # Performs a query on Skymem using a start address and email domain.
    session = requests.Session()
    session.get('http://www.skymem.info')  # To fetch cookies

    emails = []
    characters = ["", "a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","_","."]
    for letter in characters:
        query = f"{start_address}{letter} {email_domain}"
        print(f"Executing query: {query}")  # Display progress
        response = session.get(f"http://www.skymem.info/er?q={query}")
        new_emails = get_emails_from_html_skymem(response.text, start_address, email_domain)
        emails.extend(new_emails)
        print(f"Number of emails found: {len(new_emails)}")  # Display the number of new emails

    return emails

# MODULE SEARCHCODE*******************************************************************************************************

def extract_emails_from_lines(lines, start_address, domain):
    # Extracts emails from lines of code using a regex pattern.
    emails = []
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    for line in lines.values():
        found_emails = email_pattern.findall(line)
        for email in found_emails:
            if email.startswith(start_address) and email.endswith(domain):
                emails.append(email)
    return emails
    
def query_searchcode_api(start_address, domain):
    # Queries the Searchcode API for emails related to a start address and domain.
    emails = set()
    characters = ["", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "_", "."]

    for letter in characters:
        query = f"{start_address}{letter}%20%40{domain}"
        print(f"Executing query: {query}")  # Display progress
        response = requests.get(f"https://searchcode.com/api/codesearch_I/?q={query}&p=1&per_page=100")
        if response.status_code == 200:
            results = response.json()
            for result in results.get('results', []):
                new_emails = extract_emails_from_lines(result.get('lines', {}), start_address, domain)
                emails.update(new_emails)

        print(f"Number of emails found: {len(emails)}")  # Display the number of emails found

    return emails 

# MODULE PUBLICWWW********************************************************************************************************

def extract_emails_from_html_publicwww(html, start_address, email_domain):
    # Extracts emails from HTML content using PublicWWW.
    email_pattern = re.compile(r'([A-Za-z0-9._%+-]+)<b>@([A-Za-z0-9.-]+)&lt')
    found_emails = email_pattern.findall(html)
    filtered_emails = [f"{email[0]}@{email[1]}" for email in found_emails if email[0].startswith(start_address) and email[1].endswith(email_domain)]
    return filtered_emails

def query_publicwww(driver, start_address, email_domain):
    # Queries PublicWWW for emails related to a start address and domain.
    urls = [
        f"https://publicwww.com/?q=%22{start_address}%22+%22%40{email_domain}%3C%2Fp%3E%22",
        f"https://publicwww.com/?q=%22{start_address}%22+%22%40{email_domain}%3C%2Fp%3E%22/2",
        f"https://publicwww.com/?q=%22mail%22+%22{start_address}%22+%22%40{email_domain}%3C%2Fp%3E%22",
        f"https://publicwww.com/?q=%22mail%22+%22{start_address}%22+%22%40{email_domain}%3C%2Fp%3E%22/2"
    ]

    all_emails = set()
    for i, url in enumerate(urls, start=1):
        print(f"Executing query {i} of {len(urls)}")
        driver.get(url)
        time.sleep(5)  # Wait a bit to ensure the page is fully loaded
        html = driver.page_source
        emails = extract_emails_from_html_publicwww(html, start_address, email_domain)
        all_emails.update(emails)

    print(f"Found emails: {len(all_emails)}")
    return list(all_emails)

# MODULE PROSPEO.IO*******************************************************************************************************

def extract_emails_from_html_prospeo(html, start_address, email_domain):
    # Extracts emails from HTML content using Prospeo.io.
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    found_emails = email_pattern.findall(html)
    filtered_emails = [email for email in found_emails if email.startswith(start_address) and email.endswith(email_domain)]
    return filtered_emails

def query_prospeo(driver, start_address, email_domain):
    # Queries Prospeo.io for emails related to a start address and domain.
    driver.get("https://prospeo.io")
    time.sleep(3)  # Wait for cookies to load

    driver.get(f"https://prospeo.io/domain-search/{email_domain}")
    print('Executing query')
    time.sleep(10)  # Wait for the page to fully load

    html = driver.page_source

    filtered_emails = extract_emails_from_html_prospeo(html, start_address, email_domain)
    print(f"Found emails: {len(filtered_emails)}")
    return filtered_emails

# MODULE ANYMAILFINDER****************************************************************************************************

def extract_emails_from_html_anymailfinder(html, start_address, email_domain):
    # Extracts emails from HTML content using Anymailfinder.
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    found_emails = email_pattern.findall(html)
    filtered_emails = [email for email in found_emails if email.startswith(start_address) and email.endswith(email_domain)]
    return filtered_emails

def query_anymailfinder(driver, start_address, email_domain):
    # Queries Anymailfinder for emails related to a start address and domain.
    driver.get("https://newapp.anymailfinder.com/search/single")
    time.sleep(5)  # Wait for the page to load

    input_field = driver.find_element(By.CSS_SELECTOR, 'input[name="company"]')
    input_field.send_keys(email_domain)

    search_button = driver.find_element(By.CSS_SELECTOR, 'button.button_filled__DpsGq')
    search_button.click()

    time.sleep(5)  # Adjust this time depending on how long the page takes to load

    html = driver.page_source

    filtered_emails = extract_emails_from_html_anymailfinder(html, start_address, email_domain)
    print(f"Found emails after filtering: {len(filtered_emails)}")
    return filtered_emails

# MODULE EMAIL-FORMAT.COM*************************************************************************************************

def extract_emails_from_html_emailformat(html, start_address, email_domain):
    # Extracts emails from HTML content using Email-Format.com.
    soup = BeautifulSoup(html, 'html.parser')
    emails = []

    email_elements = soup.find_all('td', class_='td_email')
    for element in email_elements:
        email_div = element.find('div', class_='fl')
        if email_div:
            email_text = email_div.get_text(strip=True)
            if email_text:
                emails.append(email_text)    

    found_emails = emails
    filtered_emails = [email for email in found_emails if email.startswith(start_address) and email.endswith(email_domain)]

    return filtered_emails

def query_emailformat(start_address, email_domain):
    # Queries Email-Format.com for emails related to a start address and domain.
    url = f"https://www.email-format.com/d/{email_domain}/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close"
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        found_emails = extract_emails_from_html_emailformat(response.text, start_address, email_domain)
    else:
        print("An error occurred while fetching the page.")

    print(f"Found emails: {len(found_emails)}")

    return found_emails

# MODULE EMAILCHECKER.INFO************************************************************************************************

def handle_consent(driver):
    # Handles consent pop-up if present.
    try:
        consent_button = WebDriverWait(driver, 5).until(
            EC.element_to_be_clickable((By.XPATH, "//p[text()='Consent']"))
        )
        consent_button.click()
    except Exception as e:
        print("No cookie popup found or other error: ", e)

def scroll_to_and_click(driver, element):
    # Scrolls to an element and clicks it.
    try:
        actions = ActionChains(driver)
        actions.move_to_element(element).perform()
        element.click()
    except Exception as e:
        print(f"Error clicking on element: {e}")

def extract_emails(html, start_address, email_domain, email_regex):
    # Extracts emails from HTML content.
    found_emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', html)
    filtered_emails = [email for email in found_emails if email.startswith(start_address) and email.endswith(email_domain)]
    return filtered_emails

def retry_click(driver, by, value, retries=3):
    # Attempts to click an element multiple times if necessary.
    attempts = 0
    while attempts < retries:
        try:
            element = WebDriverWait(driver, 10).until(EC.element_to_be_clickable((by, value)))
            scroll_to_and_click(driver, element)
            return True
        except Exception as e:
            print(f"Attempt {attempts + 1} failed: {e}")
            attempts += 1
            time.sleep(2)
    return False

def extract_from_url_page(driver, start_address, email_domain, email_regex):
    # Extracts emails from a URL page.
    try:
        print(f"Starting search on URL page for domain: {email_domain}")
        driver.get("https://emailchecker.info/extract-email-from-website-url.php")
        handle_consent(driver)
        WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.ID, "url"))).send_keys(f"https://www.{email_domain}")
        if retry_click(driver, By.NAME, "EmailExtractor"):
            WebDriverWait(driver, 20).until(EC.text_to_be_present_in_element_value((By.NAME, "EmailExtractor"), "Extract Email Now"))
            time.sleep(5)
            emails_html = driver.find_element(By.ID, "div-target").get_attribute('innerHTML')
            filtered_emails = extract_emails(emails_html, start_address, email_domain, email_regex)
            print(f"Query completed. {len(filtered_emails)} emails found after filtering.")
            return filtered_emails, "https://emailchecker.info/extract-email-from-website-url.php"
    except Exception as e:
        print(f"Could not complete the search due to an error: {e}")
    return [], "https://emailchecker.info/extract-email-from-website-url.php"

def extract_from_domain_page(driver, search_terms, start_address, email_domain, email_regex):
    # Extracts emails from a domain page.
    results = []
    for index, term in enumerate(search_terms, start=1):
        try:
            print(f"Starting query {index} of {len(search_terms)}: {term}")
            driver.get("https://emailchecker.info/email-extractor.php")
            WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.NAME, "keyword"))).send_keys(term)
            WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.NAME, "otherSiteSearch"))).send_keys(email_domain)
            WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.NAME, "otherEmailSearch"))).send_keys(email_domain)
            if retry_click(driver, By.ID, "emailSearch1") and retry_click(driver, By.NAME, "EmailExtractor"):
                WebDriverWait(driver, 60).until_not(lambda d: "Email Extracting" in d.find_element(By.ID, "div-target").text)
                time.sleep(5)
                emails_html = driver.find_element(By.ID, "div-target").get_attribute('innerHTML')
                found_emails = extract_emails(emails_html, start_address, email_domain, email_regex)
                print(f"Query {index} completed. {len(found_emails)} emails found after filtering.")
                results.extend(found_emails)
        except Exception as e:
            print(f"Error during query {index}: {e}")
            continue  # Continue with the next search term
    return results, "https://emailchecker.info/email-extractor.php"

# MODULE GREP.APP*********************************************************************************************************

def get_emails_from_grep_app(query, email_domain):
    # Retrieves emails from Grep.app using a query.
    base_url = "https://grep.app/api/search"
    emails = []
    page = 1
    while True:
        print(f"Executing query {page}...")  # Inform the user about the progress
        params = {
            'q': query,
            'regexp': 'true',
            'format': 'e',
            'page': page
        }
        response = requests.get(base_url, params=params)
        if response.status_code == 200:
            data = response.json()
            if not data['hits']['hits']:
                print("No further results found.")
                break  # No results, stop searching
            for hit in data['hits']['hits']:
                snippet = hit['content']['snippet']
                found_emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', snippet)
                emails.extend(found_emails)
            print(f"Query {page} completed. {len(found_emails)} new emails found.")  # Inform the user about the results of this page
            page += 1
        else:
            print(f"Error fetching data: {response.status_code}")
            break
    return emails

def filter_emails(emails, start_address, email_domain):
    # Filters emails based on a start address and domain.
    filtered_emails = [email for email in emails if email.startswith(start_address) and email.endswith(email_domain)]
    return filtered_emails

def save_emails_to_csv(emails, filename='emailadressen.csv'):
    # Saves emails to a CSV file.
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Source', 'Domain Name', 'Email Address'])
        for email in emails:
            writer.writerow(['grep.app', email.split('@')[-1], email])

# MODULE SOURCEGRAPH******************************************************************************************************

def get_emails_from_sourcegraph(query):
    # Retrieves emails from Sourcegraph using a query.
    url = "https://sourcegraph.com/search/stream"
    params = {
        'q': f"context:global {query} count:all",
        'v': 'V3',
        't': 'regexp',
        'sm': '0',
        'display': '10000',
        'cm': 't',
        'max-line-len': '11000'
    }
    headers = {
        "Accept": "text/event-stream",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1.70.3775.400 QQBrowser/10.6.4208.400",
        "Accept-Language": "en-US,en;q=0.8,nl;q=0.5,da;q=0.3"
    }

    try:
        with requests.get(url, params=params, headers=headers, stream=True) as r:
            with open('output.txt', 'w', encoding='utf-8') as f_out:  # Open the file to write
                for line in r.iter_lines():
                    if line:
                        decoded_line = line.decode('utf-8')
                        f_out.write(decoded_line + '\n')  # Write the raw JSON data to the file
                        if 'data:' in decoded_line:
                            data_json = json.loads(decoded_line.split('data: ', 1)[1])
                        elif 'event: done' in decoded_line:
                            break
    except Exception as e:
        print(f"Error during request: {e}")
        return []

    # Extract email addresses from the file
    emails = []
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    with open('output.txt', 'r', encoding='utf-8') as f:
        content = f.read()
        emails = re.findall(email_regex, content)

    return emails

def filter_emails_sourcegraph(emails, start_address, email_domain):
    # Filters emails from Sourcegraph based on a start address and domain.
    filtered_emails = [email for email in emails if email.startswith(start_address) and email.endswith(email_domain)]
    return filtered_emails

# MODULE NETLAS.IO********************************************************************************************************

def filter_emails_netlas(emails, start_address, email_domain):
    # Filters emails from Netlas.io based on a start address and domain.
    filtered_emails = [email for email in emails if email.startswith(start_address) and email.endswith(email_domain)]
    return filtered_emails

def get_emails_from_netlas(query):
    # Retrieves emails from Netlas.io using a query.
    url = "https://app.netlas.io/api/responses/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1.70.3775.400 QQBrowser/10.6.4208.400",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.8,nl;q=0.5,da;q=0.3"
    }
    params = {
        "q": query,
        "start": "0",
        "indices": ""
    }

    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        if "Daily request limit exceeded" in response.text:
            print("Netlas daily free limit exceeded.")
            return None
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        found_emails = email_pattern.findall(response.text)
        return found_emails
    else:
        if response.status_code == 429:
            print("Netlas daily free limit exceeded.")
            return None
        else:
            print(f"Request failed with status code: {response.status_code}")
            return []

# MODULE HUNTER.IO********************************************************************************************************

def filter_emails_hunter(emails, start_address, email_domain):
    # Filters emails from Hunter.io based on a start address and domain.
    filtered_emails = [email for email in emails if email.startswith(start_address) and email.endswith(email_domain)]
    return filtered_emails

def vraag_hunter_api_key():
    # Asks the user for the Hunter.io API key.
    apikeys_file = 'apikeys.txt'
    api_hunter = " "  # Default value if no key is provided

    # Check if the file exists
    if os.path.exists(apikeys_file):
        with open(apikeys_file, 'r') as file:
            keys = file.readlines()
            hunter_key = None
            for key in keys:
                if key.startswith('hunter:'):
                    hunter_key = key.split(':')[1].strip()
                    break
            
            if hunter_key:
                # If a Hunter.io API key is found, ask the user to confirm
                confirmation = input(f"\nHunter.io API key found: {hunter_key}. Press Enter to confirm or enter a new one: ").strip()
                if confirmation:
                    api_hunter = confirmation
                else:
                    api_hunter = hunter_key
            else:
                # Ask the user for the API key if it's not in the file
                api_hunter = input("Enter your Hunter.io API key: ").strip()
    else:
        # If the file does not exist, ask for the API key and create the file
        api_hunter = input("Enter your Hunter.io API key: ").strip()
        if api_hunter:
            with open(apikeys_file, 'w') as file:
                file.write(f'hunter:{api_hunter}\n')

    # Check if the user entered anything
    if not api_hunter:
        # If the user left the field blank, set api_hunter to an empty string
        api_hunter = " "
    
    return api_hunter

def get_emails_hunter(api_hunter, email_domain):
    # Retrieves emails from Hunter.io for a given domain.
    url = f"https://api.hunter.io/v2/domain-search?domain={email_domain}&api_key={api_hunter}"

    try:
        response = requests.get(url)
        response_data = response.json()

        # Check for errors in the response
        if response.status_code != 200 or "errors" in response_data:
            print("An error occurred while fetching data from Hunter.io.")
            # Specific error messages can be handled here, for example:
            if response.status_code == 401:
                print("Authentication failed: Check your API key.")
            elif response.status_code == 429:
                print("Limit exceeded: You have reached your daily request limit.")
            return None

        # If there are no errors, process the email addresses
        emails = [email['value'] for email in response_data.get("data", {}).get("emails", [])]
        return emails

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while connecting to Hunter.io: {e}")
        return None

# MODULE SNOV.IO**********************************************************************************************************

def vraag_gebruikersnaam_wachtwoord():
    # Asks the user for their Snov.io username and password.
    print("\nType your username and password for Snov.io below (press Enter to skip)")
    gebruikersnaam = input("Enter your username: ").strip()
    wachtwoord = input("Enter your password: ").strip()

    if not gebruikersnaam or not wachtwoord:
        return None, None

    return gebruikersnaam, wachtwoord

def filter_emails_snov(emails, start_address, email_domain):
    # Filters emails from Snov.io based on a start address and domain.
    filtered_emails = [email for email in emails if email.startswith(start_address) and email.endswith(email_domain)]
    return filtered_emails

def get_emails_snov(driver, gebruikersnaam, wachtwoord, email_domain):
    # Retrieves emails from Snov.io for a given domain.
    try:
        driver.get("https://app.snov.io/login")
        # Enter username and password
        gebruikersnaam_veld = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, '//input[@data-test="email"]'))
        )
        gebruikersnaam_veld.send_keys(gebruikersnaam)

        wachtwoord_veld = WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, '//input[@data-test="password"]'))
        )
        wachtwoord_veld.send_keys(wachtwoord)

        # Click the login button
        login_button = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, '//button[@data-test="submit-form"]'))
        )
        login_button.click()

        # Wait for the page to load
        #WebDriverWait(driver, 20).until(EC.url_contains("dashboard"))

        time.sleep(12)  # Extra wait time for certainty

        # Find emails for a specific domain
        #search_url = f"https://app.snov.io/domain-search?name={email_domain}&tab=emails"
        driver.get(f"https://app.snov.io/domain-search?name={email_domain}&tab=emails")

        # Wait for the data to load
        #WebDriverWait(driver, 30).until(
        #    lambda d: d.find_elements(By.CSS_SELECTOR, ".choice__item--active .choice__item-label") and
        #              not "No records found." in d.page_source
        #)
        time.sleep(15)  # Extra wait time for certainty

        # Retrieve the data and filter out the emails
        page_source = driver.page_source
        email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_regex, page_source)

        return emails
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

# MODULE ANALYZE EMAILS.CSV & COLLECT NEW EMAILS************************************************************************

def analyze_csv_for_top_characters(csv_path, prefix):
    # Analyzes a CSV file for the top characters following a prefix.
    email_regex = re.compile(rf'{re.escape(prefix)}(\w)')
    char_counter = Counter()

    with open(csv_path, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            match = email_regex.search(row['Email Address'])
            if match:
                char_counter[match.group(1)] += 1

    top_chars = [char for char, _ in char_counter.most_common(5)]
    return top_chars

def append_emails_to_csv(csv_path, new_emails, email_domain):
    # Appends new emails to a CSV file.
    with open(csv_path, 'a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        for email in new_emails:
            writer.writerow(['Skymem', email_domain, email, md5_hash(email)])

# MAIN SCRIPT************************************************************************************************************

def main():
    # Main function to execute the email scraping tool.
    user_email = start_questions()
    api_hunter = vraag_hunter_api_key()
    gebruikersnaam, wachtwoord = vraag_gebruikersnaam_wachtwoord()

    email_pattern = user_email.replace('*', '[a-zA-Z0-9._%+-]*').replace('@', '@')
    email_regex = re.compile(email_pattern)
    email_domain = user_email.split('@')[-1]
    start_address = user_email.split('*')[0]

    with open('emailadressen.csv', 'w', newline='') as file, open('domeinnamen-met-andere-emailadressen.csv', 'w', newline='') as no_emails_file:
        writer = csv.writer(file)
        no_emails_writer = csv.writer(no_emails_file)
        writer.writerow(['Source', 'Domain Name', 'Email Address', 'MD5 Hash'])
        no_emails_writer.writerow(['Domain Name'])

        # Code for querying data from intelx and phonebook-------------------------------------------------------

        info_login_intelx()
        # Start a Selenium Chrome session
        chrome_options = Options()
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

        login_intelx(driver)
        show_login_success_popup(driver)

        restart_na_login_intelx()
        # Retrieve emails from phonebook.cz
        intelx_phonebook_emails = get_emails_phonebook(driver, email_domain, start_address, email_regex)
        driver.quit()

        for email in intelx_phonebook_emails:
            hash_value = md5_hash(email)
            writer.writerow(['phonebook.cz', email_domain, email, hash_value])

        # Start a Selenium browser with options for headless browsing
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

        # Code for querying domain names from viewdns--------------------------------------------------------------
        domain_names = get_domains_viewdns(driver, user_email)

        # Initialization for whoishistory, chinaz.tv, and os.ai
        no_emails_found = []            
        first_query = True
        total_queries = len(domain_names)
        completed_queries = 0

        # Code for querying emails from chinaz.tv and os.ai -------------------------------------------------------
        print("Searching for email addresses from whois history")
        for domain in domain_names:
            completed_queries += 1
            print(f"Processing query {completed_queries} of {total_queries}: {domain}")

            whois_data = query_whois_os_ai(domain)
            emails = extract_emails_from_whois_data(whois_data, email_regex)

            if not emails:
                html_chinaz = get_html_from_url_chinaz(f'https://chinaz.tv/whoishistory/{domain}', driver, first_query)
                first_query = False
                emails = extract_emails_chinaz(html_chinaz, email_pattern)

            if emails:
                for email in emails:
                    hash_value = md5_hash(email)
                    writer.writerow([f'https://whois.os.ai/get_domain_history?domain={domain}', domain, email, hash_value])
            else:
                no_emails_writer.writerow([domain])

        # Code for querying data from crt.sh----------------------------------------------------------------------
        crt_sh_results = query_crt_sh(email_domain, email_regex)
        print("Searching for email addresses on crt.sh") 
        for url, common_name, email in crt_sh_results:
            hash_value = md5_hash(email)
            writer.writerow([url, common_name, email, hash_value])

        # New code for querying data from Skymem------------------------------------------------------------------
        skymem_results = query_skymem(start_address, email_domain)
        print("Searching for email addresses on skymem.info") 
        for email in skymem_results:
            hash_value = md5_hash(email)
            writer.writerow(['Skymem', email_domain, email, hash_value])

        # New code for querying data from Searchcode--------------------------------------------------------------
        searchcode_results = query_searchcode_api(start_address, email_domain)
        print("Searching for email addresses on searchcode.com") 
        for email in searchcode_results:
            hash_value = md5_hash(email)
            writer.writerow(['SearchCode', email_domain, email, hash_value])

        # New code for querying data from Publicwww--------------------------------------------------------------
        print("Searching for email addresses on publicwww") 
        publicwww_results = query_publicwww(driver, start_address, email_domain)
        for email in publicwww_results:
            hash_value = md5_hash(email)
            writer.writerow(['PublicWWW', email_domain, email, hash_value])

        # New code for querying data from Prospeo.io-------------------------------------------------------------
        print("Searching for email addresses on prospeo.io") 
        prospeo_results = query_prospeo(driver, start_address, email_domain)
        for email in prospeo_results:
            hash_value = md5_hash(email)
            writer.writerow([f"prospeo.io/domain-search/{email_domain}", email_domain, email, hash_value])

        # New code for querying data from anymailfinder---------------------------------------------------------
        print("Searching for email addresses on anymailfinder") 
        anymailfinder_results = query_anymailfinder(driver, start_address, email_domain)
        for email in anymailfinder_results:
            hash_value = md5_hash(email)
            writer.writerow([f'https://newapp.anymailfinder.com/search/single', email_domain, email, hash_value])

        # New code for querying data from emailformat-----------------------------------------------------------
        print("Searching for email addresses on email-format.com") 
        emailformat_results = query_emailformat(start_address, email_domain)
        for email in emailformat_results:
            hash_value = md5_hash(email)
            writer.writerow([f'https://www.email-format.com/d/{email_domain}', email_domain, email, hash_value])

        # New code for querying data from emailchecker.info----------------------------------------------------
        print("Searching for email addresses on emailchecker.info") 
        emails, source = extract_from_url_page(driver, start_address, email_domain, email_regex)
        for email in emails:
            hash_value = md5_hash(email)
            writer.writerow([source, email_domain, email, hash_value])

        # New code for querying data from emailchecker.info / 2nd part
        search_terms = ["privacy", "contact", "email", "about-us", "team", email_domain, f"{start_address}* "]
        emails, source = extract_from_domain_page(driver, search_terms, start_address, email_domain, email_regex)
        for email in emails:
            hash_value = md5_hash(email)
            writer.writerow([source, email_domain, email, hash_value])

        # New code for querying emails from Grep.app------------------------------------------------------------
        print("Searching for emails from Grep.app")
        # First query
        query1 = f"{start_address}[A-Za-z0-9._%+-]+@{email_domain}"
        emails1 = get_emails_from_grep_app(query1, email_domain)

        # Second query
        query2 = f"<{start_address}.*@{email_domain}"
        emails2 = get_emails_from_grep_app(query2, email_domain)

        # Filter emails from both queries
        combined_emails = list(set(emails1 + emails2))
        result_grep = filter_emails(combined_emails, start_address, email_domain)
   
        for email in result_grep:
            hash_value = md5_hash(email)
            writer.writerow([f'grep.app/search/?q=', email_domain, email, hash_value])

        print(f"Data saved in emailadressen.csv. Number of found emails: {len(result_grep)}")

        # Code for querying emails from sourcegraph.com--------------------------------------------------------
        print("Searching for emails from sourcegraph.com")
        query1 = f"{start_address}[A-Za-z0-9._%+-]+@{email_domain}"
        emails1 = get_emails_from_sourcegraph(query1)
        print(f"number{len(emails1)}")

        time.sleep(5)  # Wait a bit between queries

        query2 = f"<{start_address}.*@{email_domain}"
        emails2 = get_emails_from_sourcegraph(query2)
        print(f"number {len(emails2)}")

        combined_emails = list(set(emails1 + emails2))

        result_sourcegraph = filter_emails_sourcegraph(combined_emails, start_address, email_domain)
        print(f"After filtering and removing duplicates, {len(result_sourcegraph)} email addresses remain")

        for email in result_sourcegraph:
            hash_value = md5_hash(email)
            writer.writerow(['sourcegraph.com/search/?q=', email_domain, email, hash_value])

        print(f"Data saved in emailadressen.csv. Number of unique emails found: {len(result_sourcegraph)}")

        # At the end of the sourcegraph function or after the last time output.txt is used
        if os.path.exists('output.txt'):
            os.remove('output.txt')
        else:
            print("The file output.txt does not exist and cannot be deleted.")

        # Code to retrieve emails from netlas.io--------------------------------------------------------------------
        print("Searching for emails from netlas.io")

        # These are the queries. Fill in as desired
        queries = [
            f"http.contacts.email:{start_address}* AND http.contacts.email:{email_domain}",
            f"ftp.contacts.email:{start_address}* AND ftp.contacts.email:{email_domain}",
            f"ftp.contacts.email:{start_address}* AND ftp.contacts.email:{email_domain}",
            f"certificate.issuer.email_address:{start_address}* AND certificate.issuer.email_address:{email_domain}"
        ]

        combined_emails = []

        for query in queries:
            emails = get_emails_from_netlas(query)
            if emails is None: # Check for limit exceeded
                print("Netlas daily free limit exceeded.")
                break # Stop the loop, but do not end the function
            print(f"number {len(emails)}")
            combined_emails.extend(emails)
            time.sleep(5) # Wait a bit between queries

        # Remove duplicate email addresses
        unique_emails = list(set(combined_emails))
        # Filter addresses that match the email pattern
        result_netlas = filter_emails_netlas(unique_emails, start_address, email_domain)
        print(f"After filtering and removing duplicates, {len(result_netlas)} email addresses remain")

        for email in result_netlas:
            hash_value = md5_hash(email)
            writer.writerow(['app.netlas.io/responses/search/?q=', email_domain, email, hash_value])

        print(f"Data saved in emailadressen.csv. Number of unique emails found: {len(result_netlas)}")

        # Code to retrieve emails from hunter.io-----------------------------------------------------------------

        if api_hunter is not None:
            print("Searching for emails on hunter.io")
            result_hunter = get_emails_hunter(api_hunter, email_domain)
            print(f"number of emails found: {len(result_hunter)}")
            filtered_emails = filter_emails_hunter(result_hunter, start_address, email_domain)

            for email in filtered_emails:
                hash_value = md5_hash(email)
                writer.writerow(['api.hunter.io/v2/domain-search?', email_domain, email, hash_value])

            print(f"Found emails after filtering by pattern: {len(filtered_emails)}")
            print("Data saved in emailadressen.csv.")

        else:
            print("No Hunter.io apikey entered. Module not executed.")

        # New code for querying data from Snov.io-----------------------------------------------------------------
        if gebruikersnaam != None and wachtwoord != None:
            print("Searching for emails on snov.io")
            emails = get_emails_snov(driver, gebruikersnaam, wachtwoord, email_domain)
            print(f"number of emails found: {len(emails)}")
            result_snov = filter_emails_snov(emails, start_address, email_domain)
            print(f"After filtering by pattern, {len(result_snov)} email addresses remain")

            for email in result_snov:
                hash_value = md5_hash(email)
                writer.writerow(['sourcegraph.com/search/?q=', email_domain, email, hash_value])

            print(f"Data saved in emailadressen.csv. Number of unique emails found: {len(result_snov)}")

        else:
            print("Skipped the snov.io module. No username or password input.")   

    # Conclusion
    print("Data saved in emailadressen.csv and domeinnamen-met-andere-emailadressen.csv.")
    driver.quit()

    # ANALYZE EMAILS & COLLECT NEW EMAILS ON SKYMEM------------------------------------------------------------
    csv_path = 'emailadressen.csv'
    prefix = start_address

    # Analyze the CSV file for top 5 characters
    print("Analyzing email addresses")
    top_chars = analyze_csv_for_top_characters(csv_path, prefix)
    print(f"Most used characters after prefix '{start_address}' are: {top_chars}")

    print("Collecting new email addresses on skymem.info")
    # Collect new email addresses with the top 5 characters
    all_new_emails = []
    for char in top_chars:
        new_prefix = prefix + char
        new_emails = query_skymem(new_prefix, email_domain)
        all_new_emails.extend(new_emails)
        time.sleep(10)  # Avoid overloading the server

    # Add new email addresses to the CSV
    append_emails_to_csv(csv_path, all_new_emails, email_domain)
    print("Data saved in emailadressen.csv")

if __name__ == "__main__":
    main()
