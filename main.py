import random
import string
import hashlib
import base64
import json


class PureHybridCrypto:
    def __init__(self, key="defaultkey", rounds=2, salt_len=4):
        self.key = key
        self.rounds = rounds
        self.salt_len = salt_len
        self.salt = None  # stored during encryption for consistency

    # === XOR Helper ===
    def _get_xor_key(self, length, salt=""):
        # Mix salt into key derivation for stronger variability
        hash_bytes = hashlib.sha256((self.key + salt).encode()).digest()
        return [b for b in hash_bytes[:length]]

    def _xor_encrypt(self, text, salt=""):
        key_bytes = self._get_xor_key(len(text), salt)
        return ''.join(chr(ord(c) ^ key_bytes[i % len(key_bytes)]) for i, c in enumerate(text))

    def _xor_decrypt(self, text, salt=""):
        return self._xor_encrypt(text, salt)  # XOR is symmetric

    # === Salt Handling ===
    def _add_salt(self, text):
        self.salt = ''.join(random.choices(string.ascii_letters + string.digits, k=self.salt_len))
        return self.salt + text

    def _remove_salt(self, salted_text):
        return salted_text[self.salt_len:]

    # === Shuffle Helpers ===
    def _generate_pattern(self, length, round_idx=0):
        hashed = hashlib.sha256((self.key + str(round_idx)).encode()).hexdigest()
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

    # === Core Encrypt/Decrypt ===
    def encrypt(self, text):
        text = self._add_salt(text)
        for r in range(self.rounds):
            pattern = self._generate_pattern(len(text), r)
            text = self._shuffle(text, pattern)
        text = self._xor_encrypt(text, self.salt)
        # Encode safely with Base64
        return base64.urlsafe_b64encode(text.encode("utf-8")).decode("utf-8")

    def decrypt(self, encrypted_b64):
        text = base64.urlsafe_b64decode(encrypted_b64.encode("utf-8")).decode("utf-8")
        text = self._xor_decrypt(text, self.salt or "")
        for r in reversed(range(self.rounds)):
            pattern = self._generate_pattern(len(text), r)
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
    bundle = {"k": key, "r": rounds, "s": salt_len, "d": encrypted}
    return json.dumps(bundle)

def decrypt_with_config(bundle_json):
    bundle = json.loads(bundle_json)
    crypto = PureHybridCrypto(bundle["k"], int(bundle["r"]), int(bundle["s"]))
    return crypto.decrypt(bundle["d"])


# === Double Layer (with integrity) ===
STATIC_KEY = "CladSecureKey2025"
STATIC_CRYPTO = PureHybridCrypto(STATIC_KEY, rounds=1, salt_len=4)

def encrypt_with_double_layer(text):
    bundle_json = encrypt_with_config(text)  # dynamic encryption
    integrity = hashlib.sha256(bundle_json.encode()).hexdigest()[:16]
    package = json.dumps({"b": bundle_json, "i": integrity})
    return STATIC_CRYPTO.encrypt(package)

def decrypt_with_double_layer(encrypted_text):
    decrypted_once = STATIC_CRYPTO.decrypt(encrypted_text)
    package = json.loads(decrypted_once)
    bundle_json, integrity = package["b"], package["i"]

    # integrity check
    calc_hash = hashlib.sha256(bundle_json.encode()).hexdigest()[:16]
    if calc_hash != integrity:
        raise ValueError("❌ Integrity check failed!")
    return decrypt_with_config(bundle_json)


# === Demo ===
if __name__ == "__main__":
    text = input("Text to Encrypt: ")
    print("🔓 Original:", text)

    encrypted_final = encrypt_with_double_layer(text)
    print("📦 Double Encrypted:", encrypted_final)

    bundle_new = input("Text to Decrypt: ")
    decrypted = decrypt_with_double_layer(bundle_new)
    print("✅ Decrypted:", decrypted)
