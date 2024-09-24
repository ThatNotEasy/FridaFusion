# FridaFusion
A seamless tool for injecting Frida Gadget into APKs, bridging security and dynamic analysis with ease.
**FridaFusion** is a powerful Python-based tool designed for tampering with Android APK files to enhance security analysis, penetration testing, and application debugging. This tool provides a streamlined process for modifying APKs by injecting the Frida gadget for dynamic instrumentation, altering Smali code, and manipulating application metadata.

#### Key Features:

1. **APK Decoding**: 
   - APKTool decodes Android APK files using the `apktool` command, allowing users to access and modify the underlying structure, including resources and the AndroidManifest.xml file.

2. **Frida Gadget Injection**: 
   - The tool enables seamless injection of the Frida gadget into APKs, facilitating dynamic analysis and runtime manipulation of the application.

3. **Customizable Hooks**: 
   - Users can modify Smali code to insert custom hooks, allowing them to extend or alter the application's functionality during runtime.

4. **Version Code Tampering**: 
   - APKTool provides the ability to increment version codes in the `apktool.yml` file, making it easier to test modified versions of applications without conflicts.

5. **APK Building and Signing**: 
   - After modifications, APKTool rebuilds the APK and signs it using a generated keystore, ensuring that the modified APK can be installed on devices without integrity issues.

6. **Logging and Error Handling**: 
   - The tool includes comprehensive logging to provide insights into the process and troubleshoot any errors that may arise during execution.

7. **Certificate Management**: 
   - Users can convert DER certificates to PEM format and generate new certificates as needed for secure communication with proxy servers.

#### Command-Line Arguments

The script accepts the following command-line arguments:

- `-a` or `--target-apk`:  
  **Required**  
  Specify the path to the target APK file you want to modify.

- `-c` or `--proxy-cert`:  
  **Optional**  
  Specify the path to the proxy certificate in DER format. This is used for secure communication with proxy servers.

- `-g` or `--frida-gadget`:  
  **Required**  
  Specify the path to the Frida gadget file that will be injected into the APK.

- `-r` or `--device-arch`:  
  **Required**  
  Specify the device architecture (e.g., `x86`, `arm`, etc.) for the APK modification.

#### Example Usage

To run the script, use the following command:

```bash
python main.py -a path/to/your.apk -c path/to/certificate.der -g path/to/frida-gadget.so -r x86
```

# Decoding
![image](https://github.com/user-attachments/assets/de4ca5b8-4389-4c3a-983f-fb45e45bf185)

# Injecting & Re-Building
![image](https://github.com/user-attachments/assets/f7deed0d-9ea8-49b3-836c-1474240f5846)

# Demo
https://github.com/user-attachments/assets/74e00ed0-cc50-44d9-9a6f-1b507b4c4d1b






