import multiprocessing
import hashlib
import sys
import codecs
import time

def hash_password(password, hashfunc):
    if hashfunc == "MD5":
        return hashlib.md5(password).hexdigest()
    elif hashfunc == "SHA-1":
        return hashlib.sha1(password).hexdigest()
    elif hashfunc == "SHA-256":
        return hashlib.sha256(password).hexdigest()
    elif hashfunc == "SHA-512":
        return hashlib.sha512(password).hexdigest()
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

def main(dictionary, encoding, hashfunc, hash_file):
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
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
