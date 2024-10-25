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
    parser.add_argument('-c', '--proxy-cert', help='Proxy certificate in DER format (optional)')
    parser.add_argument('-r', '--device-arch', required=True, help='Device architecture (e.g., arm64-v8a, x86, etc.)')

    args = parser.parse_args()
    logger = setup_logging()

    try:
        apk_tool = APKTool(args.target_apk, args.device_arch, args.proxy_cert)
        frida_gadget = apk_tool.get_frida_gadget()
        if not frida_gadget:
            logger.error(f"No Frida gadget found for architecture: {args.device_arch}")
            return

        logger.debug(f"{Fore.GREEN}GENERATING CERTIFICATE...")
        pem = apk_tool.generate_cert()
        apk_tool.decode_app()
        apk_tool.tamper_app(pem)

    except Exception as e:
        logger.error(f"An error occurred: {e}")

if __name__ == "__main__":
    main()