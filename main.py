import random
import string
import hashlib

class PureHybridCrypto:
    def __init__(self, key="defaultkey", rounds=2, salt_len=4):
        self.key = key
        self.rounds = rounds
        self.salt_len = salt_len

    def _get_xor_key(self, length):
        hash_bytes = hashlib.sha256(self.key.encode()).digest()
        return [b for b in hash_bytes[:length]]

    def _xor_encrypt(self, text):
        key_bytes = self._get_xor_key(len(text))
        return ''.join(chr(ord(c) ^ key_bytes[i % len(key_bytes)]) for i, c in enumerate(text))

    def _xor_decrypt(self, text):
        return self._xor_encrypt(text)  # XOR is symmetric

    def _add_salt(self, text):
        salt = ''.join(random.choices(string.ascii_letters + string.digits, k=self.salt_len))
        return salt + text

    def _remove_salt(self, salted_text):
        return salted_text[self.salt_len:]

    def _generate_pattern(self, length):
        hashed = hashlib.sha256(self.key.encode()).hexdigest()
        nums = [int(c, 16) for c in hashed[:length]]
        return sorted(range(length), key=lambda x: nums[x % len(nums)])

    def _inverse_pattern(self, pattern):
        inv = [0] * len(pattern)
        for i, p in enumerate(pattern):
            inv[p] = i
        return inv

    def _shuffle(self, text, pattern):
        return ''.join([text[i] for i in pattern])

    def _unshuffle(self, text, pattern):
        inv = self._inverse_pattern(pattern)
        return ''.join([text[i] for i in inv])

    def encrypt(self, text):
        text = self._add_salt(text)
        for _ in range(self.rounds):
            pattern = self._generate_pattern(len(text))
            text = self._shuffle(text, pattern)
        text = self._xor_encrypt(text)
        return text.encode('latin1').hex()

    def decrypt(self, encrypted_hex):
        text = bytes.fromhex(encrypted_hex).decode('latin1')
        text = self._xor_decrypt(text)
        for _ in range(self.rounds):
            pattern = self._generate_pattern(len(text))
            text = self._unshuffle(text, pattern)
        return self._remove_salt(text)


# === Utility to Randomize Config ===
def random_config():
    key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    rounds = random.randint(2, 5)
    salt_len = random.randint(2, 8)
    return key, rounds, salt_len


# === Bundle Functions ===
def encrypt_with_config(text):
    key, rounds, salt_len = random_config()
    crypto = PureHybridCrypto(key, rounds, salt_len)
    encrypted = crypto.encrypt(text)
    return f"{key}|{rounds}|{salt_len}|{encrypted}"

def decrypt_with_config(bundle):
    key, rounds, salt_len, encrypted = bundle.split("|")
    crypto = PureHybridCrypto(key, int(rounds), int(salt_len))
    return crypto.decrypt(encrypted)

STATIC_KEY = "CladSecureKey2025"
STATIC_CRYPTO = PureHybridCrypto(STATIC_KEY, rounds=1, salt_len=4)

def encrypt_with_double_layer(text):
    bundle = encrypt_with_config(text)  # dynamic config-based encryption
    double_encrypted = STATIC_CRYPTO.encrypt(bundle)  # static-key encryption
    return double_encrypted

def decrypt_with_double_layer(encrypted_text):
    decrypted_once = STATIC_CRYPTO.decrypt(encrypted_text)  # static-key decryption
    return decrypt_with_config(decrypted_once)  # dynamic decryption

if __name__ == "__main__":
    text = input("Text that has to be Encrypted: ")
    print("🔓 Original:", text)

    encrypted_final = encrypt_with_double_layer(text)
    bundle = encrypt_with_config(text)
    print("Single Encryption: ",bundle)
    print("📦 Double Encrypted:", encrypted_final)

    bundle_new = input("Text that has to be Decrypted: ")
    decrypted = decrypt_with_double_layer(bundle_new)
    print("✅ Decrypted:", decrypted)