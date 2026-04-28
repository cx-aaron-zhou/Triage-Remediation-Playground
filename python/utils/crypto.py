import hashlib

# A02:Cryptographic Failures — MD5 used for password hashing (broken algorithm)
# MD5 is cryptographically broken and unsuitable for password storage

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

def verify_password(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash
