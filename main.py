import argparse
import os
from modules.banners import banners
from modules.handler import APKTool
from modules.logger import setup_logging
from colorama import Fore

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    clear_terminal()
    banners()

    parser = argparse.ArgumentParser(description='APK Tool for modifying APK files.')
    parser.add_argument('-a', '--target-apk', required=True, help='Target APK file')
    parser.add_argument('-p', '--proxy-cert', required=False, help='Proxy certificate file')
    parser.add_argument('-r', '--device-arch', required=True, help='Device architecture (e.g., arm64-v8a, x86, etc.)')

    args = parser.parse_args()
    logger = setup_logging()

    apk_tool = APKTool(args.target_apk, args.device_arch, args.proxy_cert)
    pem = apk_tool.generate_cert()
    apk_tool.tamper_app(pem)

if __name__ == "__main__":
    main()