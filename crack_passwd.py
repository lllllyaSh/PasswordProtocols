import multiprocessing
import hashlib
import sys
import codecs
import time
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

def check_password(password, hashfunc, hashes):
    hashed = hash_password(password.encode(), hashfunc)
    if hashed in hashes:
        return password + ':' + hashed
    else:
        return None

def worker(passwords, hashfunc, hashes, queue):
    for password in passwords:
        result = check_password(password, hashfunc, hashes)
        if result is not None:
            queue.put(result)

def main():
    if len(sys.argv) != 5:
        print("Usage: python crack_password.py <wordlist> <encoding> <hash_function> <hashlist>")
        sys.exit(1)

    dictionary = sys.argv[1]
    encoding = sys.argv[2]
    hashfunc = sys.argv[3].upper()
    hash_file = sys.argv[4]

    if hashfunc not in ["MD4", "MD5", "SHA1", "SHA256", "SHA512"]:
        print(
            f"Error: Unsupported hash function '{hashfunc}'. Supported functions are: MD4, MD5, SHA1, SHA256, SHA512.")
        sys.exit(1)
    if encoding not in ["UTF-8", "UTF-16-LE"]:
        print(f"Error: Unsupported encoding '{encoding}'. Supported encodings are: utf-8, utf-16-le.")
        sys.exit(1)
    
    with codecs.open(dictionary, 'r', encoding) as f:
        passwords = f.read().splitlines()

    with open(hash_file, 'r') as f:
        hashes = f.read().splitlines()

    queue = multiprocessing.Queue()

    chunk_size = len(passwords) // multiprocessing.cpu_count()
    processes = []
    start_time = time.time()
    for i in range(multiprocessing.cpu_count()):
        start = i * chunk_size
        end = None if i == multiprocessing.cpu_count() - 1 else start + chunk_size
        process = multiprocessing.Process(target=worker, args=(passwords[start:end], hashfunc, hashes, queue))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()
    end_time = time.time()
    while not queue.empty():
        print(queue.get())
    print("Время выполнения {} секунд".format(end_time - start_time))

if __name__ == "__main__":
    main()
