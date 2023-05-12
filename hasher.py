import pathlib
import hashlib

from typing import List, Optional


def get_hash(filepath: pathlib.Path) -> Optional[str]:
    try:
        with filepath.open("rb") as f:
            fbytes = f.read()
            readable_hash = hashlib.sha256(fbytes).hexdigest()
    except Exception as e:
        print(f"Error hashing file {filepath}:\n\t{e}")
        readable_hash = None

    return readable_hash


def scan_directory(directory: str) -> List[str]:
    file_hashes: List[str] = []
    dir_obj = pathlib.Path(directory)
    for path in dir_obj.rglob("*"):
        if path.is_dir():
            continue

        file_hash = get_hash(path)
        if file_hash:
            file_hashes.append(f"{path}: {file_hash}\n")

    return file_hashes


def main() -> None:
    directories = [
        "/System/Library/Kernels",
        "/System/Library/Extensions",
        "/System/Library/Frameworks",
        "Frameworks",
        "Extensions",
        "Kernels",
    ]
    file_contents: List[str] = []
    for directory in directories:
        result = scan_directory(directory)
        file_contents.extend(result)

    hashfile = pathlib.Path("hashes.txt")
    if hashfile.exists():
        hashfile = pathlib.Path("hashes-2.txt")

    with hashfile.open("a") as f:
        f.writelines(file_contents)


if __name__ == "__main__":
    main()
