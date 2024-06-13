import telebot
from telebot import types
import requests
from bs4 import BeautifulSoup
import re
import time
import urllib.parse

# Initialize your bot with the Telegram API token
bot = telebot.TeleBot('6945433492:AAHPvr6R1tqKiyyzAtZ2N2kcOy6AncEe5QY')

# Inline keyboard markup for menu
menu_markup = types.InlineKeyboardMarkup(row_width=2)
btn_xss = types.InlineKeyboardButton(text="XSS Scanning", callback_data="xss")
btn_sqli = types.InlineKeyboardButton(text="SQL Injection Scanning", callback_data="sqli")
btn_csrf = types.InlineKeyboardButton(text="CSRF Check", callback_data="csrf")
btn_dir_traversal = types.InlineKeyboardButton(text="Directory Traversal Check", callback_data="dir_traversal")
btn_ssl_tls = types.InlineKeyboardButton(text="SSL/TLS Analysis", callback_data="ssl_tls")
btn_header_analysis = types.InlineKeyboardButton(text="Header Analysis", callback_data="header_analysis")
btn_sensitive_data = types.InlineKeyboardButton(text="Sensitive Data Check", callback_data="sensitive_data")
btn_dom_xss = types.InlineKeyboardButton(text="DOM-based XSS Check", callback_data="dom_xss")
btn_auth_test = types.InlineKeyboardButton(text="Authentication Testing", callback_data="auth_test")
btn_full_scan = types.InlineKeyboardButton(text="Perform Full Scan", callback_data="full_scan")
btn_help = types.InlineKeyboardButton(text="Help", callback_data="help")
menu_markup.add(btn_xss, btn_sqli, btn_csrf, btn_dir_traversal, btn_ssl_tls, btn_header_analysis, 
                btn_sensitive_data, btn_dom_xss, btn_auth_test, btn_full_scan, btn_help)

# Command to start the bot and show menu
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "Welcome to Web Penetration Testing Bot!\n"
                          "Use the menu below to perform scans or click 'Help' for guidance.",
                 reply_markup=menu_markup)

# Handle inline menu buttons
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
    
    elif call.data == 'xss':
        bot.send_message(chat_id, "Send me a URL to scan for XSS vulnerabilities.")
    
    elif call.data == 'sqli':
        bot.send_message(chat_id, "Send me a URL to scan for SQL Injection vulnerabilities.")
    
    elif call.data == 'csrf':
        bot.send_message(chat_id, "Send me a URL to check for CSRF vulnerabilities.")
    
    elif call.data == 'dir_traversal':
        bot.send_message(chat_id, "Send me a URL to check for Directory Traversal vulnerabilities.")
    
    elif call.data == 'ssl_tls':
        bot.send_message(chat_id, "Send me a URL to analyze SSL/TLS configuration.")
    
    elif call.data == 'header_analysis':
        bot.send_message(chat_id, "Send me a URL to analyze HTTP headers for security.")
    
    elif call.data == 'sensitive_data':
        bot.send_message(chat_id, "Send me a URL to check for exposed sensitive data.")
    
    elif call.data == 'dom_xss':
        bot.send_message(chat_id, "Send me a URL to perform DOM-based XSS vulnerability checks.")
    
    elif call.data == 'auth_test':
        bot.send_message(chat_id, "Send me a URL to test authentication mechanisms.")
    
    elif call.data == 'full_scan':
        bot.send_message(chat_id, "Performing full scan (XSS, SQLi, CSRF, etc.)...\n"
                                  "This might take some time.")
        results = perform_full_scan(chat_id)
        bot.send_message(chat_id, results)
    
    # Edit original message to refresh inline buttons
    bot.edit_message_reply_markup(chat_id=chat_id, message_id=call.message.message_id, reply_markup=menu_markup)

# Command to handle URL messages
@bot.message_handler(regexp=r'^https?://')
def handle_url(message):
    url = message.text.strip()
    bot.reply_to(message, f"Scanning {url}...")
    
    # Example: Simple XSS vulnerability check
    xss_vulnerability = check_xss_vulnerability(url)
    if xss_vulnerability:
        bot.send_message(message.chat.id, f"XSS vulnerability found in {url}!")
    else:
        bot.send_message(message.chat.id, f"No XSS vulnerabilities found in {url}.")
    
    # Example: Simple SQL injection check
    sqli_vulnerability = check_sqli_vulnerability(url)
    if sqli_vulnerability:
        bot.send_message(message.chat.id, f"SQL Injection vulnerability found in {url}!")
    else:
        bot.send_message(message.chat.id, f"No SQL Injection vulnerabilities found in {url}.")

# Function to check for XSS vulnerability
def check_xss_vulnerability(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        scripts = soup.find_all('script')
        
        for script in scripts:
            if re.search(r'<\s*script[^>]*>.*<\s*/\s*script\s*>', str(script), re.I):
                return True
        
        return False
    
    except Exception as e:
        print(f"Error checking XSS vulnerability: {e}")
        return False

# Function to check for SQL injection vulnerability
def check_sqli_vulnerability(url):
    try:
        # Attempting a SQL injection by adding a single quote
        test_url = url + "'"
        response = requests.get(test_url)
        
        # Check if error messages or SQL-related content is returned
        if 'sql' in response.text.lower() or 'error' in response.text.lower():
            return True
        
        return False
    
    except Exception as e:
        print(f"Error checking SQL injection vulnerability: {e}")
        return False

# Function to perform full scan
def perform_full_scan(chat_id):
    results = []
    
    # Example: Perform XSS scan
    xss_result = check_xss_vulnerability("https://example.com")
    if xss_result:
        results.append("XSS vulnerability found in https://example.com!")
    else:
        results.append("No XSS vulnerabilities found in https://example.com.")
    
    # Example: Perform SQLi scan
    sqli_result = check_sqli_vulnerability("https://example.com")
    if sqli_result:
        results.append("SQL Injection vulnerability found in https://example.com!")
    else:
        results.append("No SQL Injection vulnerabilities found in https://example.com.")
    
    # Add more scan types as needed
    
    return "\n".join(results)

# Start the bot polling
bot.polling()
