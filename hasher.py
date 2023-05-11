import pathlib
import hashlib

from typing import Optional


def get_hash(filepath: pathlib.Path) -> Optional[str]:
    try:
        with filepath.open("rb") as f:
            fbytes = f.read()
            readable_hash = hashlib.sha256(fbytes).hexdigest()
    except Exception as e:
        print(f"Error hashing file {filepath}:\n\t{e}")
        readable_hash = None

    return readable_hash


def scan_directory(directory: str) -> None:
    dir_obj = pathlib.Path(directory)
    for path in dir_obj.rglob("*"):
        if path.is_dir():
            continue

        file_hash = get_hash(path)
        if file_hash:
            hashfile = pathlib.Path("hashes.txt")
            if hashfile.exists():
                hashfile = pathlib.Path("hashes-2.txt")

            with hashfile.open("a") as f:
                f.write(f"{path}: {file_hash}\n")


def main() -> None:
    directories = [
        "/System/Library/Kernels",
        "/System/Library/Extensions",
        "/System/Library/Frameworks",
        "Frameworks",
        "Extensions",
        "Kernels",
    ]
    for directory in directories:
        scan_directory(directory)


if __name__ == "__main__":
    main()
