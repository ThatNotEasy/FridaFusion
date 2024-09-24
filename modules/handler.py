import os
import sys
import random
import string
from shutil import copyfile
from xml.dom import minidom
from .utils import read_lines, get_matching_files
from modules.logger import setup_logging

class APKTool:
    def __init__(self, apk, frida_gadget, device_arch, proxy_cert=None):
        self.apk = apk
        self.proxy_cert = proxy_cert
        self.frida_gadget = frida_gadget
        self.device_arch = device_arch
        self.package_name = None
        self.activity_name = None
        self.logger = setup_logging()
        
        # Extract the base name of the APK file for the output directory
        self.output_dir = os.path.splitext(self.apk)[0]
        self.logger.debug(f"APKTool initialized with APK: {self.apk}, Frida Gadget: {self.frida_gadget}, Device Arch: {self.device_arch}")

    def run_command(self, description: str, command: list):
        command_str = ' '.join(command)  # Join the command list into a string
        self.logger.debug(f"Running command: {description} - {command_str}")
        
        # Execute the command
        exit_code = os.system(command_str)  # Use os.system to run the command

        if exit_code == 0:
            self.logger.debug("Command executed successfully.")
        else:
            self.logger.error(f"Command failed with return code: {exit_code}")
            raise RuntimeError(f"Command '{command_str}' failed with return code: {exit_code}")

    def convert_der_to_pem(self) -> str:
        proxy_cert_pem = "proxy-cert.pem"
        self.logger.debug("Converting DER to PEM...")
        self.run_command("Converting DER to PEM", ["openssl", "x509", "-inform", "der", "-in", self.proxy_cert, "-out", proxy_cert_pem])
        pem = self._read_pem(proxy_cert_pem)
        self.logger.debug("Conversion complete.")
        return pem

    def generate_cert(self) -> str:
        """Generate DER certificate using OpenSSL."""
        if not self.proxy_cert:
            self.logger.debug("Proxy certificate not provided.")
            return None

        self.logger.debug("Generating certificate...")
        self.run_command("Generating DER certificate", ["openssl", "x509", "-outform", "der", "-in", "proxy-cert.pem", "-out", self.proxy_cert])
        self.logger.debug("Certificate generation complete.")
        return self.proxy_cert

    def _read_pem(self, pem_file):
        self.logger.debug(f"Reading PEM file: {pem_file}")
        with open(pem_file, "r") as file:
            pem = file.read()
        if not pem:
            self.logger.debug("Incorrect certificate (use DER format)!") 
            sys.exit(2)
        self.logger.debug("PEM read successfully.")
        return pem

    def decode_app(self):
        self.run_command("Decoding APK", ["apktool", "d", f"{self.apk}", "-f", "-o", self.output_dir])
        manifest_path = os.path.join(self.output_dir, "AndroidManifest.xml")
        self._parse_manifest(manifest_path)

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

    def _increment_version_code(self, line):
        version_code = int(line.split(":")[1].strip().strip("'"))
        self.logger.debug(f"Incrementing version code from {version_code} to {version_code + 1}.")
        return version_code + 1

    def tamper_app(self, pem):
        self.logger.debug("Starting app tampering process...")

        try:
            self._inject_frida_gadget()
            self.logger.debug("Injected Frida gadget successfully.")

            self._inject_smali_hook()
            self.logger.debug("Injected Smali hook successfully.")

            self._build_apk()
            self.logger.debug("APK built successfully.")

            self._zipalign_apk()
            self.logger.debug("APK zipaligned successfully.")

            self._create_keystore()
            self.logger.debug("Keystore created successfully.")

            self._sign_apk()
            self.logger.debug("APK signed successfully.")

            self.logger.debug("[i] Finished tampering and signing!")

        except RuntimeError as e:
            self.logger.error(f"Error occurred during app tampering: {e}")
            # Handle additional error cases based on your requirements
        except Exception as e:
            self.logger.error(f"An unexpected error occurred: {e}")

    def _parse_manifest(self, manifest_path):
        if not os.path.isfile(manifest_path):
            self.logger.debug("AndroidManifest.xml not found! Aborting...")
            sys.exit(2)
        xml_doc = minidom.parse(manifest_path)
        self.package_name = xml_doc.documentElement.getAttribute("package")
        self.activity_name = self._find_main_activity(xml_doc)

    def _find_main_activity(self, xml_doc):
        activities = xml_doc.getElementsByTagName("activity")
        for activity in activities:
            if self._is_main_activity(activity):
                self.logger.debug("Main activity found.")
                return activity.getAttribute("android:name")
        self.logger.debug("Main activity not found! Aborting...")
        sys.exit(2)

    def _is_main_activity(self, activity):
        intent_filter = activity.getElementsByTagName("intent-filter")
        if intent_filter:
            actions = intent_filter[0].getElementsByTagName("action")
            return any(action.getAttribute("android:name") == "android.intent.action.MAIN" for action in actions)
        return False

    def _inject_frida_gadget(self):
        if os.path.exists(self.frida_gadget):
            lib_path = os.path.join(self.output_dir, "lib", self.device_arch)
            os.makedirs(lib_path, exist_ok=True)
            copyfile(self.frida_gadget, os.path.join(lib_path, "libfrida-gadget.so"))
            self.logger.debug("Frida gadget injected successfully.")
        else:
            self.logger.debug("Frida gadget file not found! Aborting...")
            sys.exit(2)

    def _inject_smali_hook(self):
        smali_file_path = self._find_smali_file()
        self._patch_smali_file(smali_file_path)

    def _find_smali_file(self):
        class_name = self.activity_name.split(".")[-1]
        pattern = f'*{class_name}.smali'
        matches = get_matching_files(self.output_dir, pattern)
        if matches:
            self.logger.debug("Smali file found.")
            return matches[0]
        self.logger.debug(f"Main activity [{self.activity_name}] not found! Aborting...")
        sys.exit(2)

    def _patch_smali_file(self, smali_file_path):
        self.logger.debug("Injecting smali hook...")
        lines = read_lines(smali_file_path)
        patched_lines = self._get_patched_smali_lines(lines)

        with open(smali_file_path, 'w') as smali_file_updated:
            smali_file_updated.writelines(patched_lines)
        self.logger.debug("Smali hook injection complete.")

    def _get_patched_smali_lines(self, lines):
        patched = False
        patched_lines = []
        for line in lines:
            if self._should_patch(line, patched):
                self.logger.debug("Patching smali line.")
                patched_lines.append(self._get_injected_lines(line, lines))
                patched = True
            else:
                patched_lines.append(line)
        return patched_lines

    def _should_patch(self, line, patched):
        return (".method static constructor" in line or ".method public constructor" in line) and not patched

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

    def _update_locals(self, next_line):
        new_locals_number = 1
        if ".locals" in next_line:
            locals_number = int(next_line.split(" ")[-1])
            new_locals_number = locals_number + 1
            next_line = next_line.replace(str(locals_number), str(new_locals_number))
        else:
            next_line = f"    .locals {new_locals_number}"
        self.logger.debug(f"Updated locals number to {new_locals_number}.")
        return new_locals_number, next_line

    def _build_apk(self):
        self.run_command("Building APK", ["apktool", "b", self.output_dir, "-o", f"{self.output_dir}-modified.apk"])

    def _zipalign_apk(self):
        self.run_command("Zipaligning APK", ["zipalign", "-v", "4", f"{self.output_dir}-modified.apk", f"{self.output_dir}-aligned.apk"])

    def _create_keystore(self):
        keystore_file = "my-release-key.keystore"
        self.logger.debug("Creating keystore...")

        # Check if the alias already exists
        check_command = f'keytool -list -keystore "{keystore_file}" -storepass "password"'
        if os.system(check_command) == 0:
            self.logger.error(f"Alias 'my-key-alias' already exists. Please use a different alias or delete the existing one.")
            return  # Exit or raise an exception as needed

        command = f'keytool -genkey -v -keystore "{keystore_file}" -alias "my-key-alias" -storepass "password" -keypass "password" -keyalg RSA -dname "CN=YourName, OU=YourOrgUnit, O=YourOrg, L=YourCity, S=YourState, C=YourCountry"'
        exit_code = os.system(command)
        if exit_code != 0:
            self.logger.error(f"Command '{command}' failed with return code: {exit_code}")
            raise RuntimeError(f"Command '{command}' failed with return code: {exit_code}")
        self.logger.info("Keystore created successfully.")

    def _sign_apk(self):
        self.run_command("Signing APK", ["jarsigner", "-verbose", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1", f"{self.output_dir}-aligned.apk", "my-key-alias", "-keystore", "my-release-key.keystore", "-storepass", "password"])
