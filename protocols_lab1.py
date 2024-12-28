import hashlib
import random
import sys
import codecs
from passlib.hash import nthash


def hash_password(password, hashfunc):
    if hashfunc == "MD5":
        return hashlib.md5(password).hexdigest()
    elif hashfunc == "SHA-1":
        return hashlib.sha1(password).hexdigest()
    elif hashfunc == "SHA-256":
        return hashlib.sha256(password).hexdigest()
    elif hashfunc == "SHA-512":
        return hashlib.sha512(password).hexdigest()
    elif hashfunc == "MD4":
        return nthash.hash(password)
    else:
        return None

def main():
    if len(sys.argv) != 6:
        print("Usage: python hash_generator.py <password_file> <encoding> <hash_function> <total_hashes> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    encoding = sys.argv[2]
    hashfunc = sys.argv[3]
    output_count = sys.argv[4]
    output_file = sys.argv[5]

    if hashfunc not in ["MD4", "MD5", "SHA1", "SHA256", "SHA512"]:
        print(f"Error: Unsupported hash function '{hashfunc}'. Supported functions are: MD4, MD5, SHA1, SHA256, SHA512.")
        sys.exit(1)
    if encoding not in ["UTF-8", "UTF-16-LE"]:
        print(f"Error: Unsupported encoding '{encoding}'. Supported encodings are: utf-8, utf-16.")
        sys.exit(1)
    
    with codecs.open(input_file, "r", encoding) as f:
        passwords = f.read().splitlines()

    hash_list = [hash_password(password.encode(), hashfunc) for password in passwords]

    while len(hash_list) < output_count:
        random_password = ''.join(random.choice(passwords) for _ in range(10))
        hash_list.append(hash_password(random_password.encode(), hashfunc))

    with open(output_file, "w") as f:
        for h in hash_list[:output_count]:
            f.write(h + "\n")

if __name__ == "__main__":
    main()  
