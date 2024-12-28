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

def main(input_file, encoding, hashfunc, output_count, output_file):
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
    main(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])  
