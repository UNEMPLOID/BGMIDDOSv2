import telebot
from telebot import types
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import datetime
import os

# Initialize your bot with the Telegram API token
bot = telebot.TeleBot('YOUR_TELEGRAM_BOT_TOKEN')
my_bot = telebot.TeleBot("YOUR_TELEGRAM_BOT_TOKEN")

# Chat ID and File ID of the Log File will be stored in a dictionary for future reference
chat_file_dict = {}

# TELEGRAM GROUP SUBSCRIBERS RESTRICTION
my_group = -1000000000 # Replace with your telegram group id

@my_bot.message_handler(content_types=['new_chat_members'], chat_id=my_group)
def welcome_user(user):
    user_id = user["id"]
    first_name = user['first_name']
    text = f"Welcome {first_name} to the group!"
    my_bot.send_message(my_group, text)
    bot.send_message(user_id, "Welcome to Web Penetration Testing Bot. Kindly subscribe to the channel to proceed.")

@bot.message_handler(regexp=r'^/start', chat_id=my_group)
def send_welcome(message):
    bot.reply_to(message, "Welcome to Web Penetration Testing Bot!\n"
                          "Use the menu below to perform scans or click 'Help' for guidance.", reply_markup=menu_markup)

full_scan_markup = types.InlineKeyboardMarkup(row_width=1)
full_scan_button = types.InlineKeyboardButton(text="Perform Full Scan", callback_data="full_scan")
full_scan_markup.add(full_scan_button)

# INLINE KEYBOARD
# Inline keyboard markup for menu
menu_markup = types.InlineKeyboardMarkup(row_width=2)
buttons = [types.InlineKeyboardButton(text="XSS Scanning", callback_data="xss"),
           types.InlineKeyboardButton(text="SQL Injection Scanning", callback_data="sqli"),
           types.InlineKeyboardButton(text="CSRF Check", callback_data="csrf"),
           types.InlineKeyboardButton(text="Directory Traversal Check", callback_data="dir_traversal"),
           types.InlineKeyboardButton(text="SSL/TLS Analysis", callback_data="ssl_tls"),
           types.InlineKeyboardButton(text="Header Analysis", callback_data="header_analysis"),
           types.InlineKeyboardButton(text="Sensitive Data Check", callback_data="sensitive_data"),
           types.InlineKeyboardButton(text="DOM-based XSS Check", callback_data="dom_xss"),
           types.InlineKeyboardButton(text="Authentication Testing", callback_data="auth_test"),
           types.InlineKeyboardButton(text="Help", callback_data="help"),
           types.InlineKeyboardButton(text="Perform Full Scan", callback_data="full_scan")]
menu_markup.add(*buttons)

# SAVE LOGS FOR EACH SUCCESSFUL SCAN
def log_scan(username, url, vulnerability):
    current_date = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    log_string = f"User: {username} scanned site: {url} and finds {vulnerability} on {current_date}"
    save_log(log_string)

def save_log(log_string):
    if message.chat.id not in chat_file_dict:
        file = bot.get_file(message.chat.id)
        chat_file_dict[message.chat.id] = file.file_id
        bot.send_document(my_group, file_id=file.file_id, caption=f"Log initiated for chat {message.chat.id}")
    log_file = open('logs/' + file.file_id + '.txt', 'a')
    log_file.write(log_string + '\n')
    log_file.close()
    bot.send_message(my_group, f"Successfully saved log: {log_string}")

@bot.callback_query_handler(func=lambda call: True)
def handle_menu(call):
    chat_id = call.message.chat.id

    if call.data == 'help':
        bot.send_message(chat_id, "Welcome to Web Penetration Testing Bot!\n"
                                  "You can perform various scans and checks using the menu buttons:\n"
                                  "- Click 'XSS Scanning' to check for Cross-Site Scripting vulnerabilities.\n"
                                  "- Click 'SQL Injection Scanning' to check for SQL Injection vulnerabilities.\n"
                                  "- Click 'CSRF Check' to check for Cross-Site Request Forgery vulnerabilities.\n"
                                  "- Click 'Directory Traversal Check' to check for path traversal vulnerabilities.\n"
                                  "- Click 'SSL/TLS Analysis' to analyze SSL/TLS configuration.\n"
                                  "- Click 'Header Analysis' to analyze HTTP headers for security.\n"
                                  "- Click 'Sensitive Data Check' to find exposed sensitive information.\n"
                                  "- Click 'DOM-based XSS Check' to perform DOM-based XSS vulnerability checks.\n"
                                  "- Click 'Authentication Testing' to test authentication mechanisms.\n"
                                  "- Click 'Perform Full Scan' to initiate a comprehensive scan.\n"
                                  "Feel free to explore and analyze different aspects of web security!", reply_markup=menu_markup)

    elif call.data in ['xss', 'sqli', 'csrf', 'dir_traversal', 'ssl_tls', 'header_analysis', 'sensitive_data', 'dom_xss', 'auth_test', 'full_scan']:
        bot.send_message(chat_id, f"Send me a URL to scan for "
                                  f"{call.data.replace('_', ' ').upper()} vulnerabilities.")
        bot.edit_message_reply_markup(chat_id=chat_id, message_id=call.message.message_id, reply_markup=menu_markup)

@bot.message_handler(regexp=r'^https?://', chat_id=my_group)
def handle_url(message):
    url = message.text.strip()
    username = message.from_user.first_name
    scan_type = message.json['reply_to_message']['text'].split()[-1].lower()
    vulnerability = perform_scan_by_type(scan_type, url)
    log_scan(username, url, vulnerability)
    bot.reply_to(message, f"Scanning {url} for {scan_type.upper()} vulnerabilities...\n"
                         f"{vulnerability}")

def perform_scan_by_type(scan_type, url):
    if scan_type == 'xss':
        return check_xss_vulnerability(url)
    elif scan_type == 'sqli':
        return check_sqli_vulnerability(url)
    elif scan_type == 'csrf':
        return check_csrf_vulnerability(url)
    elif scan_type == 'dir_traversal':
        return check_directory_traversal(url)
    elif scan_type == 'ssl_tls':
        return analyze_ssl_tls(url)
    elif scan_type == 'header_analysis':
        return analyze_http_headers(url)
    elif scan_type == 'sensitive_data':
        return check_sensitive_data(url)
    elif scan_type == 'dom_xss':
        return check_dom_xss(url)
    elif scan_type == 'auth_test':
        return test_authentication(url)
    return "Invalid scan type."

def load_payloads(filename):
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines()]

def check_xss_vulnerability(url):
    payloads = load_payloads('payloads/xss_payloads.txt')
    for payload in payloads:
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url)
            if payload in response.text:
                capture_and_send_screenshot_by_url(url, "XSS_Vulnerability")
                return f"XSS vulnerability found in {url} with payload {payload}!"
        except Exception as e:
            return f"Error checking XSS vulnerability: {e}"
    return f"No XSS vulnerabilities found in {url}."

def check_sqli_vulnerability(url):
    payloads = load_payloads('payloads/sqli_payloads.txt')
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url)
            if 'sql' in response.text.lower() or 'error' in response.text.lower():
                capture_and_send_screenshot_by_url(url, "SQLi_Vulnerability")
                return f"SQL Injection vulnerability found in {url} with payload {payload}!"
        except Exception as e:
            return f"Error checking SQL injection vulnerability: {e}"
    return f"No SQL Injection vulnerabilities found in {url}."

def check_csrf_vulnerability(url):
    payloads = load_payloads('payloads/csrf_payloads.txt')
    for payload in payloads:
        # Implement CSRF check with payload
        pass
    return "CSRF check functionality not implemented yet."

def check_directory_traversal(url):
    payloads = load_payloads('payloads/dir_traversal_payloads.txt')
    for payload in payloads:
        test_url = f"{url}/{payload}"
        try:
            response = requests.get(test_url)
            if 'root:' in response.text:
                capture_and_send_screenshot_by_url(url, "Dir_Traversal_Vulnerability")
                return f"Directory Traversal vulnerability found in {url} with payload {payload}!"
        except Exception as e:
            return f"Error checking Directory Traversal vulnerability: {e}"
    return f"No Directory Traversal vulnerabilities found in {url}."

def analyze_ssl_tls(url):
    pass

def analyze_http_headers(url):
    try:
        response = requests.head(url)
        headers = response.headers
        issues = []
        if 'X-Content-Type-Options' not in headers:
            issues.append('Missing X-Content-Type-Options header.')
        if 'X-Frame-Options' not in headers:
            issues.append('Missing X-Frame-Options header.')
        if 'Strict-Transport-Security' not in headers:
            issues.append('Missing Strict-Transport-Security header.')
        if 'X-XSS-Protection' not in headers:
            issues.append('Missing X-XSS-Protection header.')
        if 'X-Permitted-Cross-Domain-Policies' not in headers:
            issues.append('Missing X-Permitted-Cross-Domain-Policies header.')
        if 'Referrer-Policy' not in headers:
            issues.append('Missing Referrer-Policy header.')
        if 'Cache-Control' not in headers:
            issues.append('Missing Cache-Control header.')
        if 'Content-Security-Policy' not in headers:
            issues.append('Missing Content-Security-Policy header.')
        if len(issues) == 0:
            return "No issues found in HTTP headers."
        else:
            return "\n".join(issues)
    except Exception as e:
        return f"Error checking HTTP headers: {e}"

def capture_and_send_screenshot_by_url(url, vulnerability_name):
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--window-size=1920,1080')
    driver = webdriver.Chrome(options=chrome_options)
    driver.get(url)
    screenshot_name = f"screenshot_{vulnerability_name}.png"
    driver.save_screenshot(screenshot_name)
    driver.close()
    with open(screenshot_name, "rb") as screenshot_file:
        screenshot_file_data = screenshot_file.read()
    bot.send_photo(my_group, screenshot_file_data, caption=f"Vulnerability: {vulnerability_name}")

def perform_full_scan(chat_id):
    vulnerabilities = {}
    urls = [
        'https://example.com',  # Replace with actual website URL
        'https://example2.com'  # Replace with actual website URL
        # Add more website URLs as needed
    ]
    for url in urls:
        for scan_type in ['xss', 'sqli', 'csrf', 'dir_traversal', 'sensitive_data']:
            vulnerability = perform_scan_by_type(scan_type, url)
            if vulnerability != "Invalid scan type.":
                if scan_type not in vulnerabilities:
                    vulnerabilities[scan_type] = []
                vulnerabilities[scan_type].append(vulnerability)
    if len(vulnerabilities) == 0:
        return f"No vulnerabilities found in the full scan for the following URLs:\n{urls}"
    else:
        results = ""
        for scan_type, vulnerabilities_list in vulnerabilities.items():
            if len(vulnerabilities_list) == 0:
                results += f"No {scan_type} vulnerabilities found.\n"
            else:
                results += f"{scan_type.upper()} vulnerabilities found:\n"
                for vulnerability in vulnerabilities_list:
                    results += f"- {vulnerability}\n"
        return results

bot.polling()
