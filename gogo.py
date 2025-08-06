import os
import sys
import time
import secrets
from eth_keys import keys
from eth_keys.exceptions import ValidationError
from pybloom_live import BloomFilter
from multiprocessing import Pool, cpu_count

RICHLIST_FILE = 'richlist.txt'

def generate_random_private_key():
    return secrets.randbits(256)

def private_key_to_address(private_key_int):
    try:
        priv_key_bytes = private_key_int.to_bytes(32, byteorder='big')
        private_key = keys.PrivateKey(priv_key_bytes)
        return private_key.public_key.to_checksum_address().lower()
    except (ValueError, ValidationError, OverflowError):
        return None

def worker(args):
    bloom, richlist_set = args
    private_key_int = generate_random_private_key()
    address = private_key_to_address(private_key_int)
    if address and address in bloom and address in richlist_set:
        return private_key_int, address
    return None

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
    last_report = time.time()
    total_checked = 0
    matches_found = 0

    try:
        while True:
            results = pool.map(worker, [(bloom, richlist_set)] * num_processes)
            for result in results:
                total_checked += 1
                if result is not None:
                    priv_key_int, addr = result
                    print(f"[MATCH] Private Key: {priv_key_int} | Address: {addr}")
                    matches_found += 1

            if time.time() - last_report >= 60:
                print(f"[INFO] Checked: {total_checked:,} keys so far...")
                last_report = time.time()
    except KeyboardInterrupt:
        print("\n[STOPPED] Scanning interrupted by user.")
        pool.terminate()
        pool.join()

    print(f"\n[DONE] Total checked: {total_checked:,}")
    print(f"[DONE] Matches found: {matches_found}")

if __name__ == '__main__':
    main()
