from hashlib import sha256


def compute_file_hash(file_path):
    hasher = sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()
