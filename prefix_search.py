
#Оскільки hash-функція не оборотна, тому робимо перебір (brute force),
#щоб знайти необхідний префікс. Використовуємо hashlib, оскільки якщо 
#перебирати вручну, то це займе дуже багато часу.
import hashlib
import time


MESSAGE = b"give my friend 2 bitcoinsfor a pizza"
FIXED_PART = b"KSE-CS810POW"


def find_prefix():
    if len(FIXED_PART) != 12:
        raise ValueError("FIXED_PART must be exactly 12 bytes")

    start_time = time.time()
    counter = 0

    while True:
        counter_bytes = counter.to_bytes(8, "big")
        prefix = FIXED_PART + counter_bytes

        digest = hashlib.sha256(prefix + MESSAGE).hexdigest()

        if digest.startswith("00000000"):
            elapsed = time.time() - start_time

            print("FOUND")
            print("Counter:", counter)
            print("Prefix hex:", prefix.hex())
            print("Prefix length:", len(prefix), "bytes")
            print("Message:", MESSAGE.decode())
            print("SHA-256:", digest)
            print("Elapsed time:", elapsed, "seconds")

            return prefix, digest

        if counter % 1_000_000 == 0:
            elapsed = time.time() - start_time
            speed = counter / elapsed if elapsed > 0 else 0
            print(f"Checked {counter:,} hashes | speed: {speed:,.0f} hashes/sec")

        counter += 1


if __name__ == "__main__":
    find_prefix()