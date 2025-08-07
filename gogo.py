import os
import sys
import time
import numpy as np
from eth_keys import keys
from eth_keys.exceptions import ValidationError
from pybloom_live import BloomFilter
from multiprocessing import Pool, cpu_count, Manager

RICHLIST_FILE = 'richlist.txt'
MATCHES_FILE = 'matches.txt'
CHUNK_SIZE = 10000  # Now 10,000 per worker

def generate_random_keys_numpy(n):
    # Generate `n` random 256-bit integers using NumPy
    return np.random.randint(0, 2**256, dtype=np.uint64, size=(n, 4))

def uint256_from_chunks(chunks):
    # Combine 4x uint64 values into one 256-bit integer
    return (int(chunks[0]) << 192) | (int(chunks[1]) << 128) | (int(chunks[2]) << 64) | int(chunks[3])

def private_key_to_address(private_key_int):
    try:
        priv_key_bytes = private_key_int.to_bytes(32, byteorder='big')
        private_key = keys.PrivateKey(priv_key_bytes)
        return private_key.public_key.to_checksum_address().lower()
    except (ValueError, ValidationError, OverflowError):
        return None

def worker(args):
    bloom, richlist_set = args
    matches = []
    key_chunks = generate_random_keys_numpy(CHUNK_SIZE)
    for chunk in key_chunks:
        priv_key_int = uint256_from_chunks(chunk)
        address = private_key_to_address(priv_key_int)
        if address and address in bloom and address in richlist_set:
            matches.append((priv_key_int, address))
    return matches

def log_match_to_file(priv_key_int, address):
    with open(MATCHES_FILE, 'a') as f:
        f.write(f"Private Key: {priv_key_int} | Address: {address}\n")

def main():
    if not os.path.isfile(RICHLIST_FILE):
        print(f"[ERROR] File '{RICHLIST_FILE}' not found.")
        sys.exit(1)

    with open(RICHLIST_FILE, 'r') as f:
        addresses = [line.strip().lower() for line in f if line.strip()]

    if not addresses:
        print(f"[ERROR] '{RICHLIST_FILE}' is empty.")
        sys.exit(1)

    bloom = BloomFilter(capacity=len(addresses), error_rate=0.001)
    for addr in addresses:
        bloom.add(addr)
    richlist_set = set(addresses)

    try:
        max_processes = cpu_count()
        num_processes = int(input(f"Enter number of processes (1 to {max_processes}): "))
        if not (1 <= num_processes <= max_processes):
            print(f"Choose 1 to {max_processes} processes.")
            sys.exit(1)
    except ValueError:
        print("[ERROR] Invalid input.")
        sys.exit(1)

    print(f"\n[INFO] Starting random key scan using {num_processes} processes...")
    pool = Pool(processes=num_processes)
    total_checked = 0
    matches_found = 0
    last_report = time.time()
    start_time = last_report

    try:
        while True:
            results = pool.imap_unordered(worker, [(bloom, richlist_set)] * num_processes)
            for result_batch in results:
                total_checked += CHUNK_SIZE
                elapsed = time.time() - start_time
                hash_rate = total_checked / elapsed if elapsed > 0 else 0

                if result_batch:
                    for priv_key_int, addr in result_batch:
                        print(f"[MATCH] Private Key: {priv_key_int} | Address: {addr}")
                        log_match_to_file(priv_key_int, addr)
                        matches_found += 1

                if time.time() - last_report >= 5:
                    print(f"[INFO] Checked: {total_checked:,} keys | Matches: {matches_found} | Hashrate: {hash_rate:,.2f} keys/sec")
                    last_report = time.time()
    except KeyboardInterrupt:
        print("\n[STOPPED] Scanning interrupted by user.")
        pool.terminate()
        pool.join()

    print(f"\n[DONE] Total checked: {total_checked:,}")
    print(f"[DONE] Matches found: {matches_found}")

if __name__ == '__main__':
    main()
