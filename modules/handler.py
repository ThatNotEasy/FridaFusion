import os
import sys
import random
import string
import shutil
import zipfile
import time
import subprocess
from shutil import copyfile
from xml.dom import minidom
from .utils import read_lines, get_matching_files
from xml.etree import ElementTree as ET
from modules.logger import setup_logging
from colorama import Fore

class APKTool:
    def __init__(self, apk, device_arch, proxy_cert=None):
        self.apk = apk
        self.proxy_cert = proxy_cert
        self.device_arch = device_arch
        self.architectures = ['x86', 'x86_64', 'armeabi', 'armeabi-v7a', 'arm64-v8a', 'mips', 'mips64', 'arm64']
        self.package_name = None
        self.activity_name = None
        self.logger = setup_logging()
        self.output_dir = os.path.splitext(self.apk)[0]
        self.frida_gadget = self.get_frida_gadget()
        self.logger.debug(f"{Fore.GREEN}APK: {Fore.YELLOW}{self.apk} {Fore.RED}| {Fore.GREEN}GADGET: {Fore.YELLOW}{self.frida_gadget} {Fore.RED}| {Fore.GREEN}DEVICE: {Fore.YELLOW}{self.device_arch}{Fore.RESET}")
        
    def modify_architecture(self):
        """ Modify the APK to support multiple architectures by adding the necessary libraries and injecting the Frida gadget. """
        self.logger.debug("Unzipping APK...")
        os.makedirs(self.output_dir, exist_ok=True)

        if self.device_arch not in self.architectures:
            self.logger.error(f"Invalid device architecture: {self.device_arch}. Supported architectures are: {self.architectures}.")
            return

        arch_dir = os.path.join(self.output_dir, 'lib', self.device_arch)
        os.makedirs(arch_dir, exist_ok=True)

        return self.inject_frida_gadget(self.device_arch)


# =================================================================================================================================== #

    def get_frida_gadget(self):
        arch_to_gadget = {
            'armeabi-v7a': f'gadget/{self.device_arch}/frida-gadget-16.5.6-android-arm.so',
            'arm64-v8a': f'gadget/{self.device_arch}/frida-gadget-16.5.6-android-arm64.so',
            'x86': f'gadget/{self.device_arch}/frida-gadget-16.5.6-android-x86.so',
            'x86_64': f'gadget/{self.device_arch}/frida-gadget-16.5.6-android-x86_64.so',
            'arm64': f'gadget/{self.device_arch}/frida-gadget-16.5.6-android-arm64.so',
        }
        
        gadget = arch_to_gadget.get(self.device_arch)
        if not gadget:
            self.logger.error(f"No Frida gadget found for architecture: {self.device_arch}")
            sys.exit(2)

        if not os.path.isfile(gadget):
            self.logger.error(f"Frida gadget file does not exist: {gadget}")
            sys.exit(2)
        
        return gadget

# =================================================================================================================================== #

    def run_command(self, description: str, command: list):
        command_str = ' '.join(command)
        # self.logger.debug(f"Running command: {description} - {command_str}")
        
        # Execute the command
        exit_code = os.system(command_str)  # Use os.system to run the command

        if exit_code == 0:
            pass
        else:
            self.logger.error(f"Command failed with return code: {exit_code}")
            raise RuntimeError(f"Command '{command_str}' failed with return code: {exit_code}")
        
# =================================================================================================================================== #

    def convert_der_to_pem(self) -> str:
        proxy_cert_pem = "proxy-cert.pem"
        self.logger.debug("Converting DER to PEM...")
        self.run_command("Converting DER to PEM", ["openssl", "x509", "-inform", "der", "-in", self.proxy_cert, "-out", proxy_cert_pem])
        pem = self._read_pem(proxy_cert_pem)
        self.logger.debug("Conversion complete.")
        return pem

# =================================================================================================================================== #

    def generate_cert(self) -> str:
        """Generate DER certificate using OpenSSL."""
        # Define the path for the proxy certificate
        proxy_cert_path = "proxy-cert.pem"
        if not os.path.isfile(proxy_cert_path):
            self.logger.debug(f"{Fore.RED}PROXY CERTIFICATE NOT FOUND. {Fore.GREEN}GENERATING A NEW ONE...{Fore.RESET}")
            time.sleep(1)

            self.logger.debug(f"{Fore.GREEN}GENERATING SELF-SIGNED CERTIFICATE: {Fore.YELLOW}{proxy_cert_path}{Fore.RESET}")
            self.run_command(f"{Fore.GREEN}GENERATING SELF-SIGNED CERTIFICATE: {Fore.YELLOW}{proxy_cert_path}{Fore.RESET}", [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "private.key", 
                "-out", proxy_cert_path, "-days", "365", "-nodes",
                "-subj", "/CN=FridaFussion"
            ])
            time.sleep(1)
            self.logger.debug(f"{Fore.GREEN}SELF-SIGNED CERTIFICATE GENERATION COMPLETE.{Fore.RESET}")
        
        if not self.proxy_cert:
            time.sleep(1)
            self.logger.debug(f"{Fore.RED}PROXY CERTIFICATE NOT PROVIDED.{Fore.RESET}")
            return None

        self.run_command(f"{Fore.GREEN}GENERATING DER CERTIFICATE: {Fore.YELLOW}{proxy_cert_path}{Fore.RESET}", [
            "openssl", "x509", "-outform", "der", "-in", proxy_cert_path, "-out", self.proxy_cert
        ])
        self.logger.debug(f"{Fore.GREEN}CERTIFICATE GENERATION COMPLETE.{Fore.RESET}")
        return self.proxy_cert

# =================================================================================================================================== #

    def _read_pem(self, pem_file):
        self.logger.debug(f"Reading PEM file: {pem_file}")
        with open(pem_file, "r") as file:
            pem = file.read()
        if not pem:
            self.logger.debug("Incorrect certificate (use DER format)!") 
            sys.exit(2)
        self.logger.debug("PEM read successfully.")
        return pem

# =================================================================================================================================== #

    def decode_app(self):
        self.run_command(f"{Fore.GREEN}DECODING APKs{Fore.RESET}", ["apktool", "d", f"{self.apk}", "-f", "-o", self.output_dir])
        manifest_path = os.path.join(self.output_dir, "AndroidManifest.xml")
        self._parse_manifest(manifest_path)

# =================================================================================================================================== #

    def tamper_yml(self):
        yml_file_path = os.path.join(self.output_dir, "apktool.yml")
        self.logger.debug("Tampering yml file...")
        lines = read_lines(yml_file_path)

        with open(yml_file_path, 'w') as yml_file_updated:
            for line in lines:
                if "versionCode:" in line:
                    new_version_code = self._increment_version_code(line)
                    line = line.replace(line.split(":")[1].strip(), str(new_version_code))
                yml_file_updated.write(line)
        self.logger.debug("YML tampering complete.")

# =================================================================================================================================== #

    def _increment_version_code(self, line):
        version_code = int(line.split(":")[1].strip().strip("'"))
        self.logger.debug(f"Incrementing version code from {version_code} to {version_code + 1}.")
        return version_code + 1

# =================================================================================================================================== #

    def tamper_app(self, pem):
        """ Start the app tampering process. """
        time.sleep(1)
        self.logger.debug(f"{Fore.GREEN}STARTING APP TAMPERING PROCESS...{Fore.RESET}")

        try:
            self.decode_app()
            time.sleep(1)
            
            self.modify_architecture()
            time.sleep(1)
            self.logger.debug(f"{Fore.GREEN}APK MODIFIED SUCCESSFULLY.{Fore.RESET}")

            self._inject_smali_hook()
            time.sleep(1)
            self.logger.debug(f"{Fore.GREEN}INJECTED SMALI HOOK SUCCESSFULLY.{Fore.RESET}")

            # Build APK
            self.recompile_apk()
            time.sleep(1)
            self.logger.debug(f"{Fore.GREEN}APK RECOMPILE SUCCESSFULLY.{Fore.RESET}")

            # Zipalign APK
            self._zipalign_apk()
            time.sleep(1)
            self.logger.debug(f"{Fore.GREEN}APK ZIPALIGNED SUCCESSFULLY.{Fore.RESET}")

            # Create keystore
            self._create_keystore()
            time.sleep(1)
            self.logger.debug(f"{Fore.GREEN}KEYSTORE CREATED SUCCESSFULLY.{Fore.RESET}")

            # Sign APK
            self._sign_apk()
            time.sleep(1)
            self.logger.debug(f"{Fore.GREEN}APK SIGNED SUCCESSFULLY.{Fore.RESET}")

        except RuntimeError as e:
            self.logger.error(f"Error occurred during app tampering: {e}")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred: {e}")

# =================================================================================================================================== #

    def _parse_manifest(self, manifest_path):
        if not os.path.isfile(manifest_path):
            self.logger.debug("AndroidManifest.xml not found! Aborting...")
            sys.exit(2)
        xml_doc = minidom.parse(manifest_path)
        self.package_name = xml_doc.documentElement.getAttribute("package")
        self.activity_name = self._find_main_activity(xml_doc)

# =================================================================================================================================== #

    def _find_main_activity(self, xml_doc):
        activities = xml_doc.getElementsByTagName("activity")
        for activity in activities:
            if self._is_main_activity(activity):
                time.sleep(1)
                self.logger.debug(f"{Fore.GREEN}MAIN ACTIVITY FOUND: {Fore.YELLOW}{activity.getAttribute('android:name')}{Fore.RESET}")
                return activity.getAttribute("android:name")
        self.logger.debug("Main activity not found! Aborting...")
        sys.exit(2)

# =================================================================================================================================== #

    def _is_main_activity(self, activity):
        intent_filter = activity.getElementsByTagName("intent-filter")
        if intent_filter:
            actions = intent_filter[0].getElementsByTagName("action")
            return any(action.getAttribute("android:name") == "android.intent.action.MAIN" for action in actions)
        return False

# =================================================================================================================================== #

    def inject_frida_gadget(self, arch):
        """ Inject Frida gadget into the APK for the specified architecture. """
        lib_path = os.path.join(self.output_dir, "lib", arch)
        destination = os.path.join(lib_path, "libfrida-gadget.so")
        if os.path.exists(self.frida_gadget):
            copyfile(self.frida_gadget, destination)
            self.logger.debug(f"{Fore.GREEN}GADGET INJECTED TO: {Fore.YELLOW}{self.frida_gadget} {Fore.RED}| {Fore.YELLOW}{lib_path}{Fore.RESET}")
        else:
            self.logger.error(f"Frida gadget file not found! Aborting for architecture: {arch}")
            sys.exit(2)

# =================================================================================================================================== #

    def _inject_smali_hook(self):
        smali_file_path = self._find_smali_file()
        self._patch_smali_file(smali_file_path)

# =================================================================================================================================== #

    def _find_smali_file(self):
        class_name = self.activity_name.split(".")[-1]
        pattern = f'*{class_name}.smali'
        matches = get_matching_files(self.output_dir, pattern)
        if matches:
            self.logger.debug(f"{Fore.GREEN}SMALI FILE FOUND: {Fore.YELLOW}{matches}{Fore.RESET}")
            return matches[0]
        self.logger.debug(f"Main activity [{self.activity_name}] not found! Aborting...")
        sys.exit(2)

# =================================================================================================================================== #

    def _patch_smali_file(self, smali_file_path):
        self.logger.debug(f"{Fore.GREEN}INJECTING SMALI HOOK...{Fore.RESET}")
        lines = read_lines(smali_file_path)
        patched_lines = self._get_patched_smali_lines(lines)

        with open(smali_file_path, 'w') as smali_file_updated:
            smali_file_updated.writelines(patched_lines)
        self.logger.debug(f"{Fore.GREEN}SMALI HOOK INJECTION COMPLETED.{Fore.RESET}")

# =================================================================================================================================== #

    def _get_patched_smali_lines(self, lines):
        patched = False
        patched_lines = []
        for line in lines:
            if self._should_patch(line, patched):
                self.logger.debug(f"{Fore.GREEN}PATCHING SMALI LINE.{Fore.RESET}")
                patched_lines.append(self._get_injected_lines(line, lines))
                patched = True
            else:
                patched_lines.append(line)
        return patched_lines

# =================================================================================================================================== #

    def _should_patch(self, line, patched):
        return (".method static constructor" in line or ".method public constructor" in line) and not patched

# =================================================================================================================================== #

    def _get_injected_lines(self, line, lines):
        next_line = lines[lines.index(line) + 1]
        
        # Update locals and get the modified next line
        new_locals_number, next_line = self._update_locals(next_line)

        frida_gadget_line = f"    const-string v{new_locals_number - 1}, \"frida-gadget\"\n"
        frida_lib_call_line = f"    invoke-static {{v{new_locals_number - 1}}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
        
        # Combine lines appropriately, ensuring not to duplicate .locals
        if ".locals" not in line and ".locals" not in next_line:
            return line + next_line + frida_gadget_line + frida_lib_call_line
        else:
            return line + frida_gadget_line + frida_lib_call_line

# =================================================================================================================================== #

    def _update_locals(self, next_line):
        new_locals_number = 1
        if ".locals" in next_line:
            locals_number = int(next_line.split(" ")[-1])
            new_locals_number = locals_number + 1
            next_line = next_line.replace(str(locals_number), str(new_locals_number))
        else:
            next_line = f"    .locals {new_locals_number}"
        self.logger.debug(f"{Fore.GREEN}UPDATED LOCALS NUMBER TO: {Fore.YELLOW}{new_locals_number}{Fore.RESET}.")
        return new_locals_number, next_line

# =================================================================================================================================== #

    def recompile_apk(self):
        self.run_command(f"{Fore.GREEN}BUILDING APKs: {Fore.YELLOW}{self.output_dir}{Fore.RESET}", ["apktool", "b", self.output_dir])

# =================================================================================================================================== #

    def _zipalign_apk(self):
        """
        Zipalign the APK to optimize it for size and performance.
        """
        recompile_apk = f"{self.output_dir}/dist/{self.output_dir}.apk"
        zipaligned_apk = f"{self.output_dir}/dist/{self.output_dir}_zipaligned.apk"
        
        self.logger.debug(f"{Fore.GREEN}ZIPALIGNED APK...{Fore.RESET}")
        time.sleep(1)
        self.run_command("Zipaligning APK", ["zipalign", "-v", "4", f"{recompile_apk}", f"{zipaligned_apk}"])
        self.logger.debug(f"{Fore.GREEN}APK ZIPALIGNED AS: {Fore.YELLOW}{zipaligned_apk}.{Fore.RESET}")

# =================================================================================================================================== #

    def _create_keystore(self):
        """
        Create a keystore for signing the APK.
        """
        keystore_file = "FridaFussion.keystore"
        time.sleep(1)
        self.logger.debug(f"{Fore.GREEN}CREATING KEYSTORE: {Fore.YELLOW}{keystore_file}{Fore.RESET}")
        
        dname = '"CN=FridaFussion, OU=FridaFussion, O=FridaFussion, L=New York, S=NY, C=US"'
        
        self.run_command("Creating Keystore", [
            "keytool", "-genkey", "-v", "-keystore", keystore_file, "-alias", "FridaFussion", 
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000", 
            "-dname", dname,
            "-storepass", "FridaFussion", "-keypass", "FridaFussion"
        ])
        self.logger.debug(f"Keystore created as {keystore_file}.")

# =================================================================================================================================== #

    def _sign_apk(self):
        """
        Sign the APK using the created keystore.
        """
        signed_apk = f"{self.output_dir}_zipaligned.apk"
        keystore = "FridaFussion.keystore"
        keystore_password = "FridaFussion"  # Replace with the actual password or securely fetch it
        self.logger.debug("Signing APK...")
        self.run_command("Signing APK", [
            "apksigner", "sign", "--ks", keystore, "--ks-pass", f"pass:{keystore_password}", 
            "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
            signed_apk
        ])
        self.logger.debug(f"APK signed as {signed_apk}.")