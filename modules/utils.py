import subprocess
import os
import fnmatch

def read_lines(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def run_command(message, command):
    print(message)
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        exit(1)

def get_matching_files(root_dir, pattern):
    matches = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in fnmatch.filter(filenames, pattern):
            matches.append(os.path.join(dirpath, filename))
    return matches