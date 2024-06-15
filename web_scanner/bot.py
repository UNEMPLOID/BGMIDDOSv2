import telebot
from telebot import types
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Initialize your bot with the Telegram API token
bot = telebot.TeleBot('YOUR_TELEGRAM_BOT_TOKEN')

# Inline keyboard markup for menu
menu_markup = types.InlineKeyboardMarkup(row_width=2)
buttons = [
    types.InlineKeyboardButton(text="XSS Scanning", callback_data="xss"),
    types.InlineKeyboardButton(text="SQL Injection Scanning", callback_data="sqli"),
    types.InlineKeyboardButton(text="CSRF Check", callback_data="csrf"),
    types.InlineKeyboardButton(text="Directory Traversal Check", callback_data="dir_traversal"),
    types.InlineKeyboardButton(text="SSL/TLS Analysis", callback_data="ssl_tls"),
    types.InlineKeyboardButton(text="Header Analysis", callback_data="header_analysis"),
    types.InlineKeyboardButton(text="Sensitive Data Check", callback_data="sensitive_data"),
    types.InlineKeyboardButton(text="DOM-based XSS Check", callback_data="dom_xss"),
    types.InlineKeyboardButton(text="Authentication Testing", callback_data="auth_test"),
    types.InlineKeyboardButton(text="Perform Full Scan", callback_data="full_scan"),
    types.InlineKeyboardButton(text="Help", callback_data="help")
]
menu_markup.add(*buttons)

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "Welcome to Web Penetration Testing Bot!\n"
                          "Use the menu below to perform scans or click 'Help' for guidance.",
                 reply_markup=menu_markup)

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
                                  "Feel free to explore and analyze different aspects of web security!",
                         reply_markup=menu_markup)
    elif call.data in ['xss', 'sqli', 'csrf', 'dir_traversal', 'ssl_tls', 'header_analysis', 'sensitive_data', 'dom_xss', 'auth_test']:
        bot.send_message(chat_id, f"Send me a URL to scan for {call.data.replace('_', ' ').upper()} vulnerabilities.")
    elif call.data == 'full_scan':
        bot.send_message(chat_id, "Performing full scan (XSS, SQLi, CSRF, etc.)...\n"
                                  "This might take some time.")
        results = perform_full_scan(chat_id)
        bot.send_message(chat_id, results)
    bot.edit_message_reply_markup(chat_id=chat_id, message_id=call.message.message_id, reply_markup=menu_markup)

@bot.message_handler(regexp=r'^https?://')
def handle_url(message):
    url = message.text.strip()
    scan_type = message.json['reply_to_message']['text'].split()[-1].lower()
    bot.reply_to(message, f"Scanning {url} for {scan_type.upper()} vulnerabilities...")
    result = perform_scan_by_type(scan_type, url)
    bot.send_message(message.chat.id, result)

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
    return "SSL/TLS analysis functionality not implemented yet."

def analyze_http_headers(url):
    try:
        response = requests.head(url)
        headers = response.headers
        issues = []
        if 'X-Content-Type-Options' not in headers:
            issues.append('Missing X-Content-Type-Options header.')
        if 'X-Frame-Options' not in headers:
            issues.append('Missing X-Frame-Options header.')
        if 'Content-Security-Policy' not in headers:
            issues.append('Missing Content-Security-Policy header.')
        if issues:
            return f"HTTP Header Analysis for {url}: " + ", ".join(issues)
        return f"HTTP Headers for {url} are properly configured."
    except Exception as e:
        return f"Error analyzing HTTP headers: {e}"

def check_sensitive_data(url):
    return "Sensitive data exposure check functionality not implemented yet."

def check_dom_xss(url):
    return "DOM-based XSS check functionality not implemented yet."

def test_authentication(url):
    return "Authentication testing functionality not implemented yet."

def perform_full_scan(chat_id):
    results = []
    url = "https://example.com"  # Replace with actual URL to be scanned
    
    xss_result = check_xss_vulnerability(url)
    results.append(xss_result)
    
    sqli_result = check_sqli_vulnerability(url)
    results.append(sqli_result)
    
    csrf_result = check_csrf_vulnerability(url)
    results.append(csrf_result)
    
    dir_traversal_result = check_directory_traversal(url)
    results.append(dir_traversal_result)
    
    ssl_tls_result = analyze_ssl_tls(url)
    results.append(ssl_tls_result)
    
    header_analysis_result = analyze_http_headers(url)
    results.append(header_analysis_result)
    
    sensitive_data_result = check_sensitive_data(url)
    results.append(sensitive_data_result)
    
    dom_xss_result = check_dom_xss(url)
    results.append(dom_xss_result)
    
    auth_test_result = test_authentication(url)
    results.append(auth_test_result)
    
    return "\n".join(results)

def capture_and_send_screenshot_by_url(url, title):
    try:
        options = webdriver.ChromeOptions()
        options.add_argument('headless')
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        screenshot_file = f"{title}.png"
        driver.save_screenshot(screenshot_file)
        with open(screenshot_file, 'rb') as photo:
            bot.send_photo(chat_id, photo, caption=f"Screenshot of {title} at {url}")
        driver.quit()
    except Exception as e:
        bot.send_message(chat_id, f"Error capturing screenshot for {title} at {url}: {e}")

bot.polling()
