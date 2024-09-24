import argparse
import pyfiglet
import os
from modules.banners import banners
from modules.handler import APKTool
from modules.logger import setup_logging

def clear_terminal():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    
def main():
    clear_terminal()
    banners()
    
    parser = argparse.ArgumentParser(description='APK Tool for modifying APK files.')
    parser.add_argument('-a', '--target-apk', required=True, help='Target APK file')
    parser.add_argument('-c', '--proxy-cert', help='Proxy certificate in DER format')
    parser.add_argument('-g', '--frida-gadget', required=True, help='Frida gadget file')
    parser.add_argument('-r', '--device-arch', required=True, help='Device architecture (e.g., x86)')

    args = parser.parse_args()

    apk_tool = APKTool(args.target_apk, args.frida_gadget, args.device_arch, args.proxy_cert)
    pem = apk_tool.generate_cert()
    apk_tool.decode_app()
    apk_tool.tamper_yml()
    apk_tool.tamper_app(pem)

if __name__ == "__main__":
    main()
