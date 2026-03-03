# =============================================================================
# BinModder - Crypto Engine Module
# =============================================================================
# Provides encryption and decryption operations for binary data.
# Implements XOR, AES (ECB/CBC/CTR), DES, Triple-DES, RC4, Blowfish,
# and ROT-based transforms. All operations work on raw bytes.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import os
import struct
from enum import Enum
from typing import Optional, Union, List, Tuple
from pathlib import Path


# =============================================================================
# Enumerations
# =============================================================================

class CipherMode(Enum):
    """Cipher modes of operation."""
    ECB = "ecb"   # Electronic Code Book
    CBC = "cbc"   # Cipher Block Chaining
    CFB = "cfb"   # Cipher Feedback
    OFB = "ofb"   # Output Feedback
    CTR = "ctr"   # Counter mode
    GCM = "gcm"   # Galois/Counter Mode


class CryptoAlgorithm(Enum):
    """Available cryptographic algorithms."""
    XOR         = "xor"
    XOR_ROLLING = "xor_rolling"
    ROT8        = "rot8"
    ROT13       = "rot13"
    ROT47       = "rot47"
    AES128      = "aes128"
    AES192      = "aes192"
    AES256      = "aes256"
    DES         = "des"
    TRIPLE_DES  = "3des"
    RC4         = "rc4"
    BLOWFISH    = "blowfish"
    CHACHA20    = "chacha20"
    CUSTOM_XOR  = "custom_xor"


class CryptoError(Exception):
    """Base exception for crypto operations."""
    pass


class KeyError(CryptoError):
    """Raised when a key is invalid."""
    pass


class PaddingError(CryptoError):
    """Raised when padding is invalid."""
    pass


# =============================================================================
# Padding Utilities
# =============================================================================

class Padding:
    """Block cipher padding implementations."""

    @staticmethod
    def pkcs7_pad(data: bytes, block_size: int) -> bytes:
        """Apply PKCS#7 padding."""
        pad_len = block_size - (len(data) % block_size)
        return data + bytes([pad_len]) * pad_len

    @staticmethod
    def pkcs7_unpad(data: bytes) -> bytes:
        """Remove PKCS#7 padding."""
        if not data:
            raise PaddingError("Empty data")
        pad_len = data[-1]
        if pad_len == 0 or pad_len > 16:
            raise PaddingError(f"Invalid PKCS#7 pad length: {pad_len}")
        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            raise PaddingError("Invalid PKCS#7 padding")
        return data[:-pad_len]

    @staticmethod
    def zero_pad(data: bytes, block_size: int) -> bytes:
        """Apply zero padding."""
        remainder = len(data) % block_size
        if remainder:
            return data + b"\x00" * (block_size - remainder)
        return data

    @staticmethod
    def zero_unpad(data: bytes) -> bytes:
        """Remove zero padding (strip trailing null bytes)."""
        return data.rstrip(b"\x00")

    @staticmethod
    def iso7816_pad(data: bytes, block_size: int) -> bytes:
        """Apply ISO/IEC 7816-4 padding."""
        data = data + b"\x80"
        remainder = len(data) % block_size
        if remainder:
            data += b"\x00" * (block_size - remainder)
        return data

    @staticmethod
    def iso7816_unpad(data: bytes) -> bytes:
        """Remove ISO/IEC 7816-4 padding."""
        idx = data.rfind(b"\x80")
        if idx == -1:
            raise PaddingError("ISO 7816-4 padding byte 0x80 not found")
        return data[:idx]


# =============================================================================
# XOR Engine
# =============================================================================

class XOREngine:
    """XOR-based encryption/decryption."""

    @staticmethod
    def xor_byte(data: bytes, key_byte: int) -> bytes:
        """XOR each byte with a single key byte."""
        key = key_byte & 0xFF
        return bytes(b ^ key for b in data)

    @staticmethod
    def xor_key(data: bytes, key: bytes) -> bytes:
        """XOR data with repeating key."""
        key_len = len(key)
        return bytes(
            data[i] ^ key[i % key_len]
            for i in range(len(data))
        )

    @staticmethod
    def xor_rolling(
        data:        bytes,
        initial_key: int,
        step:        int = 1,
        mask:        int = 0xFF,
    ) -> bytes:
        """XOR with rolling key (key increments with each byte)."""
        result = bytearray()
        key    = initial_key & mask
        for b in data:
            result.append(b ^ (key & mask))
            key = (key + step) & mask
        return bytes(result)

    @staticmethod
    def xor_nibble(data: bytes, key: int) -> bytes:
        """XOR high and low nibbles separately."""
        key_hi = (key >> 4) & 0xF
        key_lo = key & 0xF
        result = bytearray()
        for b in data:
            hi = ((b >> 4) ^ key_hi) & 0xF
            lo = (b ^ key_lo) & 0xF
            result.append((hi << 4) | lo)
        return bytes(result)

    @staticmethod
    def xor_seek(data: bytes, key: bytes, offset: int) -> bytes:
        """XOR starting from a given key offset."""
        key_len = len(key)
        return bytes(
            data[i] ^ key[(i + offset) % key_len]
            for i in range(len(data))
        )

    @staticmethod
    def find_xor_key(
        ciphertext:  bytes,
        known_plain: bytes,
        key_len:     int,
    ) -> Optional[bytes]:
        """
        Recover XOR key given known plaintext.

        Args:
            ciphertext:  Encrypted bytes
            known_plain: Known plaintext bytes
            key_len:     Expected key length

        Returns:
            Key bytes, or None if recovery fails
        """
        if len(ciphertext) < key_len or len(known_plain) < key_len:
            return None
        key = bytearray()
        for i in range(key_len):
            key.append(ciphertext[i] ^ known_plain[i])
        return bytes(key)

    @staticmethod
    def brute_xor_byte(
        data:      bytes,
        printable: bool = True,
    ) -> List[Tuple[int, bytes]]:
        """
        Try all 256 single-byte XOR keys and return printable results.

        Returns:
            List of (key, plaintext) tuples sorted by printability score
        """
        results = []
        for key in range(256):
            plaintext = XOREngine.xor_byte(data, key)
            if printable:
                score = sum(1 for b in plaintext if 0x20 <= b <= 0x7E)
                results.append((key, plaintext, score))
            else:
                results.append((key, plaintext, 0))

        results.sort(key=lambda x: x[2], reverse=True)
        return [(r[0], r[1]) for r in results]


# =============================================================================
# ROT Engine
# =============================================================================

class ROTEngine:
    """ROT-N substitution cipher implementations."""

    @staticmethod
    def rot8(data: bytes, n: int = 128) -> bytes:
        """ROT-N on byte values (circular within 0-255)."""
        return bytes((b + n) % 256 for b in data)

    @staticmethod
    def rot13_ascii(text: str) -> str:
        """ROT-13 on ASCII letters."""
        result = []
        for ch in text:
            if "a" <= ch <= "z":
                result.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= ch <= "Z":
                result.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def rot13_bytes(data: bytes) -> bytes:
        """ROT-13 on bytes (only affects ASCII letters 0x41-0x7A)."""
        result = bytearray()
        for b in data:
            if 0x61 <= b <= 0x7A:  # a-z
                result.append((b - 0x61 + 13) % 26 + 0x61)
            elif 0x41 <= b <= 0x5A:  # A-Z
                result.append((b - 0x41 + 13) % 26 + 0x41)
            else:
                result.append(b)
        return bytes(result)

    @staticmethod
    def rot47(data: bytes) -> bytes:
        """ROT-47: rotates all printable ASCII characters (0x21-0x7E)."""
        result = bytearray()
        for b in data:
            if 0x21 <= b <= 0x7E:
                result.append((b - 0x21 + 47) % 94 + 0x21)
            else:
                result.append(b)
        return bytes(result)

    @staticmethod
    def caesar(data: bytes, shift: int, charset_start: int = 0x20, charset_size: int = 95) -> bytes:
        """Generic Caesar cipher on a defined charset."""
        result = bytearray()
        for b in data:
            if charset_start <= b < charset_start + charset_size:
                result.append((b - charset_start + shift) % charset_size + charset_start)
            else:
                result.append(b)
        return bytes(result)


# =============================================================================
# RC4 Engine
# =============================================================================

class RC4Engine:
    """RC4 stream cipher (also known as ARCFOUR)."""

    def __init__(self, key: bytes):
        if not key:
            raise KeyError("RC4 key cannot be empty")
        self.key = key
        self._init_sbox()

    def _init_sbox(self) -> None:
        """Initialize the S-box with key scheduling."""
        self._sbox = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self._sbox[i] + self.key[i % len(self.key)]) % 256
            self._sbox[i], self._sbox[j] = self._sbox[j], self._sbox[i]

    def _keystream(self, length: int) -> bytes:
        """Generate RC4 keystream bytes."""
        sbox = list(self._sbox)
        i, j = 0, 0
        stream = bytearray()
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + sbox[i]) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]
            stream.append(sbox[(sbox[i] + sbox[j]) % 256])
        return bytes(stream)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt/decrypt data (RC4 is symmetric)."""
        self._init_sbox()  # Reset state
        keystream = self._keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, keystream))

    # RC4 is symmetric - encrypt == decrypt
    decrypt = encrypt

    @classmethod
    def crypt(cls, data: bytes, key: bytes) -> bytes:
        """One-shot RC4 encrypt/decrypt."""
        return cls(key).encrypt(data)


# =============================================================================
# AES Engine
# =============================================================================

class AESEngine:
    """AES encryption/decryption using pycryptodome."""

    AES_BLOCK_SIZE = 16

    def __init__(self, key: bytes, mode: CipherMode = CipherMode.CBC):
        if len(key) not in (16, 24, 32):
            raise KeyError(f"AES key must be 16, 24, or 32 bytes, got {len(key)}")
        self.key  = key
        self.mode = mode

    def _get_mode_const(self):
        """Get pycryptodome mode constant."""
        try:
            from Crypto.Cipher import AES
            mode_map = {
                CipherMode.ECB: AES.MODE_ECB,
                CipherMode.CBC: AES.MODE_CBC,
                CipherMode.CFB: AES.MODE_CFB,
                CipherMode.OFB: AES.MODE_OFB,
                CipherMode.CTR: AES.MODE_CTR,
                CipherMode.GCM: AES.MODE_GCM,
            }
            return mode_map.get(self.mode, AES.MODE_CBC)
        except ImportError:
            raise CryptoError("pycryptodome not installed. Run: pip install pycryptodome")

    def encrypt(
        self,
        data:    bytes,
        iv:      Optional[bytes] = None,
        pad:     bool = True,
    ) -> bytes:
        """
        Encrypt data with AES.

        Args:
            data: Plaintext bytes
            iv:   Initialization vector (for CBC/CFB/OFB, ignored for ECB)
            pad:  Apply PKCS#7 padding

        Returns:
            Ciphertext bytes (IV prepended if generated)
        """
        try:
            from Crypto.Cipher import AES
        except ImportError:
            raise CryptoError("pycryptodome not installed")

        mode_const = self._get_mode_const()

        if pad:
            data = Padding.pkcs7_pad(data, self.AES_BLOCK_SIZE)

        if self.mode == CipherMode.ECB:
            cipher = AES.new(self.key, AES.MODE_ECB)
            return cipher.encrypt(data)

        elif self.mode == CipherMode.CBC:
            if iv is None:
                iv = os.urandom(self.AES_BLOCK_SIZE)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return iv + cipher.encrypt(data)

        elif self.mode == CipherMode.CTR:
            if iv is None:
                iv = os.urandom(8)
            cipher = AES.new(self.key, AES.MODE_CTR, nonce=iv)
            return iv + cipher.encrypt(data)

        elif self.mode == CipherMode.GCM:
            if iv is None:
                iv = os.urandom(16)
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            return iv + tag + ciphertext

        else:
            raise CryptoError(f"Mode {self.mode} not yet implemented")

    def decrypt(
        self,
        data:   bytes,
        iv:     Optional[bytes] = None,
        unpad:  bool = True,
    ) -> bytes:
        """Decrypt data with AES."""
        try:
            from Crypto.Cipher import AES
        except ImportError:
            raise CryptoError("pycryptodome not installed")

        if self.mode == CipherMode.ECB:
            cipher = AES.new(self.key, AES.MODE_ECB)
            result = cipher.decrypt(data)
            if unpad:
                result = Padding.pkcs7_unpad(result)
            return result

        elif self.mode == CipherMode.CBC:
            if iv is None:
                iv   = data[:self.AES_BLOCK_SIZE]
                data = data[self.AES_BLOCK_SIZE:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            result = cipher.decrypt(data)
            if unpad:
                result = Padding.pkcs7_unpad(result)
            return result

        elif self.mode == CipherMode.CTR:
            if iv is None:
                iv   = data[:8]
                data = data[8:]
            cipher = AES.new(self.key, AES.MODE_CTR, nonce=iv)
            return cipher.decrypt(data)

        elif self.mode == CipherMode.GCM:
            if iv is None:
                iv   = data[:16]
                tag  = data[16:32]
                data = data[32:]
            else:
                tag  = data[:16]
                data = data[16:]
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt(data)

        else:
            raise CryptoError(f"Mode {self.mode} not yet implemented")


# =============================================================================
# DES Engine
# =============================================================================

class DESEngine:
    """DES and Triple-DES encryption/decryption."""

    DES_BLOCK_SIZE = 8

    def __init__(
        self,
        key:  bytes,
        mode: CipherMode = CipherMode.CBC,
        triple: bool = False,
    ):
        if triple:
            if len(key) not in (16, 24):
                raise KeyError(f"3DES key must be 16 or 24 bytes, got {len(key)}")
        else:
            if len(key) != 8:
                raise KeyError(f"DES key must be 8 bytes, got {len(key)}")

        self.key    = key
        self.mode   = mode
        self.triple = triple

    def _get_cipher(self, iv: Optional[bytes] = None):
        """Create pycryptodome DES cipher."""
        try:
            from Crypto.Cipher import DES, DES3
        except ImportError:
            raise CryptoError("pycryptodome not installed")

        cipher_cls = DES3 if self.triple else DES

        if self.mode == CipherMode.ECB:
            from Crypto.Cipher import DES
            return cipher_cls.new(self.key, cipher_cls.MODE_ECB)
        elif self.mode == CipherMode.CBC:
            if iv is None:
                iv = os.urandom(self.DES_BLOCK_SIZE)
            return cipher_cls.new(self.key, cipher_cls.MODE_CBC, iv), iv

        raise CryptoError(f"DES mode {self.mode} not supported")

    def encrypt(self, data: bytes, iv: Optional[bytes] = None, pad: bool = True) -> bytes:
        """Encrypt with DES/3DES."""
        if pad:
            data = Padding.pkcs7_pad(data, self.DES_BLOCK_SIZE)

        if self.mode == CipherMode.ECB:
            cipher = self._get_cipher()
            return cipher.encrypt(data)
        else:
            cipher, used_iv = self._get_cipher(iv)
            return used_iv + cipher.encrypt(data)

    def decrypt(self, data: bytes, iv: Optional[bytes] = None, unpad: bool = True) -> bytes:
        """Decrypt with DES/3DES."""
        if self.mode == CipherMode.ECB:
            cipher = self._get_cipher()
            result = cipher.decrypt(data)
        else:
            if iv is None:
                iv   = data[:self.DES_BLOCK_SIZE]
                data = data[self.DES_BLOCK_SIZE:]
            cipher, _ = self._get_cipher(iv)
            result = cipher.decrypt(data)

        if unpad:
            result = Padding.pkcs7_unpad(result)
        return result


# =============================================================================
# Blowfish Engine
# =============================================================================

class BlowfishEngine:
    """Blowfish block cipher."""

    def __init__(self, key: bytes, mode: CipherMode = CipherMode.CBC):
        if not (4 <= len(key) <= 56):
            raise KeyError(f"Blowfish key must be 4-56 bytes, got {len(key)}")
        self.key  = key
        self.mode = mode

    def encrypt(self, data: bytes, iv: Optional[bytes] = None, pad: bool = True) -> bytes:
        """Encrypt with Blowfish."""
        try:
            from Crypto.Cipher import Blowfish
        except ImportError:
            raise CryptoError("pycryptodome not installed")

        if pad:
            data = Padding.pkcs7_pad(data, 8)

        if self.mode == CipherMode.ECB:
            cipher = Blowfish.new(self.key, Blowfish.MODE_ECB)
            return cipher.encrypt(data)
        else:
            if iv is None:
                iv = os.urandom(8)
            cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
            return iv + cipher.encrypt(data)

    def decrypt(self, data: bytes, iv: Optional[bytes] = None, unpad: bool = True) -> bytes:
        """Decrypt with Blowfish."""
        try:
            from Crypto.Cipher import Blowfish
        except ImportError:
            raise CryptoError("pycryptodome not installed")

        if self.mode == CipherMode.ECB:
            cipher = Blowfish.new(self.key, Blowfish.MODE_ECB)
            result = cipher.decrypt(data)
        else:
            if iv is None:
                iv   = data[:8]
                data = data[8:]
            cipher = Blowfish.new(self.key, Blowfish.MODE_CBC, iv)
            result = cipher.decrypt(data)

        if unpad:
            result = Padding.pkcs7_unpad(result)
        return result


# =============================================================================
# Crypto Engine - Main Class
# =============================================================================

class CryptoEngine:
    """
    Unified cryptographic operations engine.

    Supports:
    - XOR (single byte, key, rolling, nibble)
    - ROT (ROT-8, ROT-13, ROT-47, Caesar)
    - RC4 stream cipher
    - AES-128/192/256 (ECB, CBC, CTR, GCM)
    - DES / Triple-DES (ECB, CBC)
    - Blowfish (ECB, CBC)
    - Key derivation utilities

    Usage:
        engine = CryptoEngine()

        # Simple XOR
        encrypted = engine.xor(data, key=b"\\xAB\\xCD")

        # AES-256-CBC
        encrypted = engine.aes256_cbc_encrypt(data, key, iv)
        decrypted = engine.aes256_cbc_decrypt(encrypted, key)

        # RC4
        encrypted = engine.rc4(data, key)
    """

    def __init__(self):
        pass

    # -------------------------------------------------------------------------
    # XOR Operations
    # -------------------------------------------------------------------------

    def xor(self, data: bytes, key: bytes) -> bytes:
        """XOR data with repeating key."""
        return XOREngine.xor_key(data, key)

    def xor_byte(self, data: bytes, key: int) -> bytes:
        """XOR data with single byte key."""
        return XOREngine.xor_byte(data, key)

    def xor_rolling(
        self, data: bytes, initial_key: int, step: int = 1
    ) -> bytes:
        """XOR with rolling/incrementing key."""
        return XOREngine.xor_rolling(data, initial_key, step)

    def xor_nibble(self, data: bytes, key: int) -> bytes:
        """XOR nibbles separately."""
        return XOREngine.xor_nibble(data, key)

    def find_xor_key(
        self, ciphertext: bytes, known_plain: bytes, key_len: int
    ) -> Optional[bytes]:
        """Recover XOR key from known plaintext."""
        return XOREngine.find_xor_key(ciphertext, known_plain, key_len)

    def brute_xor(self, data: bytes) -> List[Tuple[int, bytes]]:
        """Try all single-byte XOR keys."""
        return XOREngine.brute_xor_byte(data)

    # -------------------------------------------------------------------------
    # ROT Operations
    # -------------------------------------------------------------------------

    def rot8(self, data: bytes, n: int = 128) -> bytes:
        """ROT-N byte cipher."""
        return ROTEngine.rot8(data, n)

    def rot13(self, data: bytes) -> bytes:
        """ROT-13 on ASCII letters."""
        return ROTEngine.rot13_bytes(data)

    def rot47(self, data: bytes) -> bytes:
        """ROT-47 on printable ASCII."""
        return ROTEngine.rot47(data)

    def caesar(
        self, data: bytes, shift: int = 3,
        charset_start: int = 0x20, charset_size: int = 95
    ) -> bytes:
        """Caesar cipher."""
        return ROTEngine.caesar(data, shift, charset_start, charset_size)

    # -------------------------------------------------------------------------
    # RC4 Operations
    # -------------------------------------------------------------------------

    def rc4(self, data: bytes, key: bytes) -> bytes:
        """RC4 encrypt/decrypt (symmetric)."""
        return RC4Engine.crypt(data, key)

    def rc4_encrypt(self, data: bytes, key: bytes) -> bytes:
        return self.rc4(data, key)

    def rc4_decrypt(self, data: bytes, key: bytes) -> bytes:
        return self.rc4(data, key)

    # -------------------------------------------------------------------------
    # AES Operations
    # -------------------------------------------------------------------------

    def aes_encrypt(
        self,
        data:    bytes,
        key:     bytes,
        mode:    CipherMode = CipherMode.CBC,
        iv:      Optional[bytes] = None,
        pad:     bool = True,
    ) -> bytes:
        """AES encrypt (auto key size)."""
        return AESEngine(key, mode).encrypt(data, iv, pad)

    def aes_decrypt(
        self,
        data:   bytes,
        key:    bytes,
        mode:   CipherMode = CipherMode.CBC,
        iv:     Optional[bytes] = None,
        unpad:  bool = True,
    ) -> bytes:
        """AES decrypt (auto key size)."""
        return AESEngine(key, mode).decrypt(data, iv, unpad)

    def aes128_ecb_encrypt(self, data: bytes, key: bytes) -> bytes:
        return AESEngine(key[:16], CipherMode.ECB).encrypt(data, pad=True)

    def aes128_ecb_decrypt(self, data: bytes, key: bytes) -> bytes:
        return AESEngine(key[:16], CipherMode.ECB).decrypt(data, unpad=True)

    def aes128_cbc_encrypt(self, data: bytes, key: bytes, iv: Optional[bytes] = None) -> bytes:
        return AESEngine(key[:16], CipherMode.CBC).encrypt(data, iv)

    def aes128_cbc_decrypt(self, data: bytes, key: bytes, iv: Optional[bytes] = None) -> bytes:
        return AESEngine(key[:16], CipherMode.CBC).decrypt(data, iv)

    def aes256_ecb_encrypt(self, data: bytes, key: bytes) -> bytes:
        return AESEngine(key[:32], CipherMode.ECB).encrypt(data, pad=True)

    def aes256_ecb_decrypt(self, data: bytes, key: bytes) -> bytes:
        return AESEngine(key[:32], CipherMode.ECB).decrypt(data, unpad=True)

    def aes256_cbc_encrypt(self, data: bytes, key: bytes, iv: Optional[bytes] = None) -> bytes:
        return AESEngine(key[:32], CipherMode.CBC).encrypt(data, iv)

    def aes256_cbc_decrypt(self, data: bytes, key: bytes, iv: Optional[bytes] = None) -> bytes:
        return AESEngine(key[:32], CipherMode.CBC).decrypt(data, iv)

    # -------------------------------------------------------------------------
    # DES Operations
    # -------------------------------------------------------------------------

    def des_encrypt(
        self, data: bytes, key: bytes,
        mode: CipherMode = CipherMode.CBC, iv: Optional[bytes] = None
    ) -> bytes:
        return DESEngine(key[:8], mode).encrypt(data, iv)

    def des_decrypt(
        self, data: bytes, key: bytes,
        mode: CipherMode = CipherMode.CBC, iv: Optional[bytes] = None
    ) -> bytes:
        return DESEngine(key[:8], mode).decrypt(data, iv)

    def triple_des_encrypt(
        self, data: bytes, key: bytes,
        mode: CipherMode = CipherMode.CBC, iv: Optional[bytes] = None
    ) -> bytes:
        return DESEngine(key[:24], mode, triple=True).encrypt(data, iv)

    def triple_des_decrypt(
        self, data: bytes, key: bytes,
        mode: CipherMode = CipherMode.CBC, iv: Optional[bytes] = None
    ) -> bytes:
        return DESEngine(key[:24], mode, triple=True).decrypt(data, iv)

    # -------------------------------------------------------------------------
    # Blowfish Operations
    # -------------------------------------------------------------------------

    def blowfish_encrypt(
        self, data: bytes, key: bytes,
        mode: CipherMode = CipherMode.CBC, iv: Optional[bytes] = None
    ) -> bytes:
        return BlowfishEngine(key, mode).encrypt(data, iv)

    def blowfish_decrypt(
        self, data: bytes, key: bytes,
        mode: CipherMode = CipherMode.CBC, iv: Optional[bytes] = None
    ) -> bytes:
        return BlowfishEngine(key, mode).decrypt(data, iv)

    # -------------------------------------------------------------------------
    # Key Utilities
    # -------------------------------------------------------------------------

    def derive_key_pbkdf2(
        self,
        password:  Union[str, bytes],
        salt:      Optional[bytes] = None,
        iterations: int = 100_000,
        key_len:   int = 32,
        hash_algo: str = "sha256",
    ) -> Tuple[bytes, bytes]:
        """
        Derive a key using PBKDF2-HMAC.

        Returns:
            (key, salt) tuple
        """
        import hashlib
        if isinstance(password, str):
            password = password.encode("utf-8")
        if salt is None:
            salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac(hash_algo, password, salt, iterations, key_len)
        return key, salt

    def generate_key(self, size: int = 32) -> bytes:
        """Generate random key bytes."""
        return os.urandom(size)

    def generate_iv(self, size: int = 16) -> bytes:
        """Generate random IV bytes."""
        return os.urandom(size)

    def key_from_hex(self, hex_str: str) -> bytes:
        """Parse a key from hex string."""
        return bytes.fromhex(hex_str.replace(" ", ""))

    # -------------------------------------------------------------------------
    # Byte-Level Operations
    # -------------------------------------------------------------------------

    def byte_swap16(self, data: bytes) -> bytes:
        """Swap bytes in each 16-bit word."""
        if len(data) % 2 != 0:
            data = data + b"\x00"
        result = bytearray()
        for i in range(0, len(data), 2):
            result.append(data[i + 1])
            result.append(data[i])
        return bytes(result)

    def byte_swap32(self, data: bytes) -> bytes:
        """Swap bytes in each 32-bit dword."""
        if len(data) % 4 != 0:
            data = data + b"\x00" * (4 - len(data) % 4)
        result = bytearray()
        for i in range(0, len(data), 4):
            chunk = data[i:i + 4]
            result.extend(reversed(chunk))
        return bytes(result)

    def nibble_swap(self, data: bytes) -> bytes:
        """Swap high and low nibbles in each byte."""
        return bytes(((b & 0x0F) << 4) | ((b & 0xF0) >> 4) for b in data)

    def bit_reverse(self, data: bytes) -> bytes:
        """Reverse bits in each byte."""
        result = bytearray()
        for b in data:
            rev = 0
            for _ in range(8):
                rev = (rev << 1) | (b & 1)
                b >>= 1
            result.append(rev)
        return bytes(result)

    def invert_bits(self, data: bytes) -> bytes:
        """Invert (NOT) all bits."""
        return bytes(b ^ 0xFF for b in data)

    def add_bytes(self, data: bytes, value: int) -> bytes:
        """Add value to each byte (modulo 256)."""
        return bytes((b + value) % 256 for b in data)

    def subtract_bytes(self, data: bytes, value: int) -> bytes:
        """Subtract value from each byte (modulo 256)."""
        return bytes((b - value) % 256 for b in data)

    # -------------------------------------------------------------------------
    # ECU-Specific Operations
    # -------------------------------------------------------------------------

    def ecu_descramble_delphi(self, data: bytes, key: bytes) -> bytes:
        """Delphi ECU descramble algorithm."""
        result   = bytearray(data)
        key_len  = len(key)
        for i in range(len(result)):
            result[i] ^= key[i % key_len]
            result[i]  = (result[i] + (i & 0xFF)) & 0xFF
        return bytes(result)

    def ecu_scramble_bosch(self, data: bytes, seed: int = 0x00) -> bytes:
        """Simple Bosch ECU scramble."""
        result = bytearray()
        val    = seed & 0xFF
        for b in data:
            val = (val + b) & 0xFF
            result.append(b ^ val)
        return bytes(result)

    def ecu_descramble_bosch(self, data: bytes, seed: int = 0x00) -> bytes:
        """Reverse Bosch ECU scramble."""
        result   = bytearray()
        val      = seed & 0xFF
        prev_enc = seed & 0xFF

        for enc_byte in data:
            plain  = enc_byte ^ val
            val    = (val + plain) & 0xFF
            result.append(plain)

        return bytes(result)

    # -------------------------------------------------------------------------
    # Representation
    # -------------------------------------------------------------------------

    def list_algorithms(self) -> List[str]:
        return [a.name for a in CryptoAlgorithm]

    def __repr__(self) -> str:
        return "CryptoEngine(XOR, ROT, RC4, AES, DES, 3DES, Blowfish)"
