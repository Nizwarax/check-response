import os
import json
import socket
import ssl
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup, FeatureNotFound
import telegram
from telegram.ext import Application, CommandHandler, MessageHandler, filters
import asyncio
import concurrent.futures
from datetime import datetime
import argparse

CONFIG_FILE = "config.json"
RESULTS_DIR = "results"

def get_ip_addresses(hostname):
    """
    Resolves the IP addresses for a given hostname.
    """
    try:
        _, _, ips = socket.gethostbyname_ex(hostname)
        return ips
    except socket.gaierror:
        return []

def get_ssl_info(hostname):
    """
    Retrieves SSL/TLS information for a given hostname.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                protocol = ssock.version()
                peer_cn = "-"
                return cipher[0], protocol, peer_cn
    except (socket.gaierror, ConnectionRefusedError, ssl.SSLError, socket.timeout) as e:
        return f"Error: {e}", None, None


def get_http_response(url):
    """
    Fetches the HTTP response for a given URL.
    """
    try:
        response = requests.get(url, timeout=10)
        status_line = f"HTTP/{response.raw.version / 10.0} {response.status_code} {response.reason}"
        headers = response.headers
        return status_line, headers, response.text
    except requests.RequestException as e:
        return f"Error: {e}", {}, ""


def is_cloudflare(headers):
    """
    Checks if the server is Cloudflare.
    """
    return "cloudflare" in headers.get("Server", "").lower()

def save_config(bot_token, chat_id):
    """
    Saves the Telegram bot configuration to a file.
    """
    config = {"bot_token": bot_token, "chat_id": chat_id}
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)

def load_config():
    """
    Loads the Telegram bot configuration from a file.
    """
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return None

async def send_to_telegram(message, bot_token, chat_id):
    """
    Sends a message to a Telegram chat asynchronously.
    """
    try:
        bot = telegram.Bot(token=bot_token)
        await bot.send_message(chat_id=chat_id, text=f"```\n{message}\n```", parse_mode='MarkdownV2')
        print("Successfully sent to Telegram!")
    except Exception as e:
        print(f"Failed to send to Telegram: {e}")

def save_result_to_file(hostname, content):
    """
    Saves the analysis content to a file in the results directory.
    """
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{hostname.replace('.', '_')}_{timestamp}.txt"
    filepath = os.path.join(RESULTS_DIR, filename)

    with open(filepath, "w", encoding='utf-8') as f:
        f.write(content)

    return filepath

def get_analysis_output(target_url):
    """
    Performs the full analysis, saves it to a file, and returns the formatted output string.
    """
    parsed_url = urlparse(target_url)
    hostname = parsed_url.netloc

    ips = get_ip_addresses(hostname)
    cipher, protocol, peer_cn = get_ssl_info(hostname)
    status_line, headers, html_content = get_http_response(target_url)
    cdn_map = get_cdn_map(html_content, target_url)

    output = []
    output.append("┏━━━━━━━━━━━━━━━━ TARGET ━━━━━━━━━━━━━━━━┓")
    output.append(f"┃ URL     : {target_url:<30} ┃")
    if ips:
        for ip in ips:
            output.append(f"┃ IP      : {ip:<30} ┃")
    else:
        output.append(f"┃ IP      : {'Resolution failed':<30} ┃")
    output.append(f"┃ Cipher  : {str(cipher):<30} ┃")
    output.append(f"┃ Protocol: {str(protocol):<30} ┃")
    output.append(f"┃ Peer CN : {peer_cn:<30} ┃")
    output.append("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")

    server = headers.get("Server", "Unknown")
    status_line_with_server = f"{status_line}"
    if "cloudflare" in server.lower():
        status_line_with_server += f"\nServer: {server} ✅"
    else:
        status_line_with_server += f"\nServer: {server}"
    output.append(status_line_with_server)

    for key in ["Cache-Control", "Connection", "Content-Type", "Date", "Set-Cookie", "Transfer-Encoding", "Vary"]:
        if key in headers:
            output.append(f"{key}: {headers[key]}")

    output.append("\n📡 CDN MAP")
    sorted_cdn_map = sorted(cdn_map.items())
    for i, (domain, (ips, cdn)) in enumerate(sorted_cdn_map, 1):
        output.append(f"{i}. {domain} ({cdn})")
        if ips:
            for ip in ips:
                output.append(f"   - {ip}")
        else:
            output.append("   - (no IP)")

    final_output = "\n".join(output)
    filepath = save_result_to_file(hostname, final_output)

    return final_output, filepath

def check_domain_cdn(domain):
    """
    Helper function to check CDN for a single domain.
    This function is designed to be run in a separate thread.
    """
    ips = get_ip_addresses(domain)
    cdn = "Other/Unknown"
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        response = requests.get(f"https://{domain}", timeout=5, headers=headers)
        server_header = response.headers.get("Server", "").lower()
        if "cloudflare" in server_header:
            cdn = "Cloudflare ✅"
    except requests.RequestException:
        pass
    return domain, (ips, cdn)


def get_cdn_map(html_content, base_url):
    """
    Parses HTML to find linked domains and their IP addresses using multithreading.
    """
    try:
        soup = BeautifulSoup(html_content, "lxml")
    except FeatureNotFound:
        print("\n[!] lxml parser not found. Falling back to the built-in html.parser.")
        print("    For better performance, please install it with: pip install lxml")
        soup = BeautifulSoup(html_content, "html.parser")

    links = set()
    for tag in soup.find_all(href=True) + soup.find_all(src=True):
        url = tag.get('href') or tag.get('src')
        if url and not url.startswith(("mailto:", "tel:", "#", "javascript:")):
            try:
                parsed_link = urlparse(url)
                if parsed_link.hostname and '.' in parsed_link.hostname and parsed_link.hostname != urlparse(base_url).hostname:
                    links.add(parsed_link.hostname)
            except ValueError:
                continue

    cdn_map = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_domain = {executor.submit(check_domain_cdn, link): link for link in links}
        for future in concurrent.futures.as_completed(future_to_domain):
            try:
                domain, result = future.result()
                cdn_map[domain] = result
            except Exception as exc:
                domain_name = future_to_domain[future]
                print(f'{domain_name} generated an exception: {exc}')

    return cdn_map

async def start(update, context):
    """Handler for the /start command."""
    await update.message.reply_text(
        "Welcome to the Response Checker Bot!\n\n"
        "Send me a full URL (e.g., https://example.com) and I will analyze it for you."
    )

async def handle_message(update, context):
    """Handler for text messages, checks for URLs."""
    text = update.message.text
    if text.lower().startswith("http://") or text.lower().startswith("https://"):
        await update.message.reply_text(f"Analyzing {text}...")
        try:
            output, _ = await asyncio.to_thread(get_analysis_output, text)
            for i in range(0, len(output), 4096):
                chunk = output[i:i+4096]
                await update.message.reply_text(f"```\n{chunk}\n```", parse_mode='MarkdownV2')
        except Exception as e:
            await update.message.reply_text(f"An error occurred during analysis: {e}")
    else:
        await update.message.reply_text("Please send a valid URL starting with http:// or https://")

def run_bot(bot_token):
    """
    Runs the script in persistent bot mode.
    """
    print("Starting bot mode...")
    application = Application.builder().token(bot_token).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.run_polling()

def main():
    """
    Main function to run the response checker.
    """
    parser = argparse.ArgumentParser(description="Response Checker Script")
    parser.add_argument("--bot", action="store_true", help="Run in persistent bot mode.")
    args = parser.parse_args()

    if args.bot:
        config = load_config()
        if not config or "bot_token" not in config:
            print("Bot token not configured. Please run the script without --bot first and configure it.")
            return
        run_bot(config["bot_token"])
    else:
        while True:
            print("\nMenu:")
            print("1. Run check and display in terminal")
            print("2. Run check and send to Telegram")
            print("3. Configure Telegram Bot")
            print("4. Exit")
            choice = input("Enter your choice: ")

            if choice == "1":
                target_url = input("Enter the URL to check: ")
                print("Analyzing...")
                output, filepath = get_analysis_output(target_url)
                print(output)
                print(f"\n[+] Result saved to: {filepath}")
            elif choice == "2":
                config = load_config()
                if not config:
                    print("Telegram bot not configured. Please configure it first.")
                    continue
                target_url = input("Enter the URL to check: ")
                print("Analyzing and sending to Telegram...")
                output, filepath = get_analysis_output(target_url)
                asyncio.run(send_to_telegram(output, config["bot_token"], config["chat_id"]))
                print(f"\n[+] Result saved to: {filepath}")
            elif choice == "3":
                bot_token = input("Enter your Telegram Bot Token: ")
                chat_id = input("Enter your Telegram Chat ID: ")
                save_config(bot_token, chat_id)
                print("Configuration saved.")
            elif choice == "4":
                break
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
