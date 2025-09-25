import os
import json
import socket
import ssl
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import telegram

CONFIG_FILE = "config.json"

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
                # The peer certificate's commonName is often not available or relevant with SNI
                # so we will leave it as a placeholder.
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

def send_to_telegram(message, bot_token, chat_id):
    """
    Sends a message to a Telegram chat.
    """
    try:
        bot = telegram.Bot(token=bot_token)
        bot.send_message(chat_id=chat_id, text=message)
        print("Successfully sent to Telegram!")
    except Exception as e:
        print(f"Failed to send to Telegram: {e}")

def get_analysis_output(target_url):
    """
    Performs the full analysis and returns the formatted output string.
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

    return "\n".join(output)

def get_cdn_map(html_content, base_url):
    """
    Parses HTML to find linked domains and their IP addresses.
    """
    soup = BeautifulSoup(html_content, "lxml")
    links = set()
    tags = soup.find_all(["a", "img", "script", "link"])

    for tag in tags:
        url = ""
        if tag.name == "a" and "href" in tag.attrs:
            url = tag["href"]
        elif tag.name in ["img", "script"] and "src" in tag.attrs:
            url = tag["src"]
        elif tag.name == "link" and "href" in tag.attrs:
            url = tag["href"]

        if url and not url.startswith(("mailto:", "tel:")):
            parsed_link = urlparse(url)
            if parsed_link.hostname and parsed_link.hostname != urlparse(base_url).hostname:
                links.add(parsed_link.hostname)

    cdn_map = {}
    for link in links:
        ips = get_ip_addresses(link)
        try:
            # A simple check for cloudflare in headers of the linked domain
            response = requests.get(f"https://{link}", timeout=5)
            server_header = response.headers.get("Server", "").lower()
            cdn = "Cloudflare ✅" if "cloudflare" in server_header else "Other/Unknown"
        except requests.RequestException:
            cdn = "Other/Unknown"
        cdn_map[link] = (ips, cdn)

    return cdn_map

def main():
    """
    Main function to run the response checker.
    """
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
            output = get_analysis_output(target_url)
            print(output)
        elif choice == "2":
            config = load_config()
            if not config:
                print("Telegram bot not configured. Please configure it first.")
                continue
            target_url = input("Enter the URL to check: ")
            print("Analyzing and sending to Telegram...")
            output = get_analysis_output(target_url)
            send_to_telegram(output, config["bot_token"], config["chat_id"])
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