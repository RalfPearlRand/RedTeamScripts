import argparse
import base64
import hashlib
import itertools
import string
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

# Importação de bibliotecas para criptografia
try:
    from Crypto.Cipher import AES, DES, Blowfish, ChaCha20, ARC4
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256, SHA1, MD5, HMAC
    from Crypto.Util.Padding import unpad
    crypto_available = True
except ImportError:
    crypto_available = False

try:
    import base58
except ImportError:
    base58 = None

class CryptoBruteforcer:
    def __init__(self, payload, output_file="resultados_bruteforce.txt", verbose=True, max_workers=4):
        self.payload = payload
        self.output_file = output_file
        self.verbose = verbose
        self.results = []
        self.start_time = time.time()
        self.max_workers = max_workers

    def log(self, message):
        if self.verbose:
            print(message)
        self.results.append(message)

    def write_results(self):
        with open(self.output_file, "w", encoding="utf-8", errors="ignore") as f:
            f.write("\n".join(self.results))
        self.log(f"\nOperação concluída em {time.time() - self.start_time:.2f} segundos.")
        self.log(f"Resultados salvos em: {self.output_file}")

    def bruteforce_base_encodings(self):
        """Testa Base64, Base32, Base58, Hex, Base85, ASCII85"""
        self.log("\n==== BRUTEFORCE BASE ENCODINGS ====")
        encodings = {
            "Base64": base64.b64decode,
            "Base32": base64.b32decode,
            "Base58": base58.b58decode if base58 else None,
            "Hex": bytes.fromhex,
            "Base85": base64.b85decode,
            "ASCII85": base64.a85decode,
        }
        for name, decoder in encodings.items():
            if decoder:
                try:
                    result = decoder(self.payload).decode("utf-8", errors="ignore")
                    self.log(f"{name}: {result}")
                except:
                    pass

    def bruteforce_xor_multiple_bytes(self):
        """Bruteforce XOR com chaves de até 10 bytes"""
        self.log("\n==== BRUTEFORCE XOR (MULTIPLE BYTES) ====")
        for key in itertools.product(range(256), repeat=10):
            key_bytes = bytes(key)
            result = "".join(chr(ord(c) ^ key_bytes[i % len(key_bytes)]) for i, c in enumerate(self.payload))
            self.log(f"XOR Key {key_bytes}: {result}")

    def bruteforce_hash_detection(self):
        """Verifica se o payload é um hash comum"""
        self.log("\n==== VERIFICAÇÃO DE HASH ====")
        hash_types = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}
        if len(self.payload) in hash_types:
            self.log(f"Possível hash {hash_types[len(self.payload)]}")

    def bruteforce_aes_common_keys(self):
        """Tenta descriptografar AES usando chaves comuns"""
        if not crypto_available:
            return self.log("AES não suportado (biblioteca ausente)")
        self.log("\n==== BRUTEFORCE AES ====")
        keys = [b"0123456789abcdef", b"passwordpassword", b"adminadminadmin"]
        for key in keys:
            try:
                cipher = AES.new(key, AES.MODE_ECB)
                decrypted = unpad(cipher.decrypt(base64.b64decode(self.payload)), AES.block_size)
                self.log(f"AES Key {key}: {decrypted.decode()}")
            except:
                pass

    def bruteforce_rsa(self, private_key_pem):
        """Tenta descriptografar com uma chave privada RSA fornecida"""
        try:
            private_key = RSA.import_key(private_key_pem)
            decrypted = private_key.decrypt(base64.b64decode(self.payload))
            self.log(f"RSA Decrypted: {decrypted.decode()}")
        except:
            pass

    def run_all(self):
        """Executa todas as técnicas de descriptografia"""
        self.log(f"Iniciando análise para: {self.payload}")
        self.bruteforce_base_encodings()
        self.bruteforce_xor_multiple_bytes()
        self.bruteforce_hash_detection()
        self.bruteforce_aes_common_keys()
        self.write_results()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ferramenta de Bruteforce para Criptografia")
    parser.add_argument("payload", help="String a ser descriptografada")
    parser.add_argument("-o", "--output", default="resultados_bruteforce.txt", help="Arquivo de saída")
    args = parser.parse_args()
    bruteforcer = CryptoBruteforcer(args.payload, output_file=args.output)
    bruteforcer.run_all()
