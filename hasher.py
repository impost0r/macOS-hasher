import os
import hashlib

# List of directories to scan
directories = [
    "/System/Library/Kernels", "/System/Library/Extensions", "/System/Library/Frameworks", "Frameworks", "Extensions", "Kernels"
    # Add the rest of your directories here...
]

def hash_file(filepath):
    try:
        # Open the file in binary mode
        with open(filepath, "rb") as f:
            bytes = f.read()  # Read the whole file
            readable_hash = hashlib.sha256(bytes).hexdigest()  # Create a SHA256 hash
            return readable_hash
    except Exception as e:
        print(f"Error hashing file {filepath}: {str(e)}")
        return None

def scan_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = hash_file(filepath)
            if file_hash is not None:
                if os.path.exists("hashes.txt"):
                    with open('hashes-2.txt', 'a') as f:
                        f.write(f"{filepath}: {file_hash}\n")
                else:
                    with open('hashes.txt', 'a') as f:
                        f.write(f"{filepath}: {file_hash}\n")

# Scan all directories
for directory in directories:
    scan_directory(directory)
