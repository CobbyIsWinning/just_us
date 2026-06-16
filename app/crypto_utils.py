import base64
import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()


AES_KEY_SIZE = 32
HMAC_KEY_SIZE = 32
NONCE_SIZE = 12


class CryptoError(Exception):
    """Base exception for cryptographic failures."""


class IntegrityError(CryptoError):
    """Raised when message integrity verification fails."""


class DecryptionError(CryptoError):
    """Raised when ciphertext cannot be decrypted."""


class KeyProtectionError(CryptoError):
    """Raised when stored keys cannot be protected or recovered."""


@dataclass(frozen=True)
class MessageKeys:
    encryption_key: bytes
    hmac_key: bytes


@dataclass(frozen=True)
class EncryptedMessage:
    ciphertext: str
    nonce: str
    hmac_digest: str


def encode_bytes(value: bytes) -> str:
    """Convert bytes into a database-safe Base64 string."""
    return base64.urlsafe_b64encode(value).decode("utf-8")


def decode_bytes(value: str) -> bytes:
    """Convert a Base64 string back into bytes."""
    try:
        return base64.urlsafe_b64decode(value.encode("utf-8"))
    except Exception as error:
        raise CryptoError("Invalid Base64-encoded cryptographic value.") from error


def generate_message_keys() -> MessageKeys:
    """
    Generate separate secure random keys for AES encryption
    and HMAC integrity verification.
    """
    return MessageKeys(
        encryption_key=os.urandom(AES_KEY_SIZE),
        hmac_key=os.urandom(HMAC_KEY_SIZE),
    )


def generate_nonce() -> bytes:
    """
    Generate a new 96-bit nonce.

    A fresh nonce must be generated for every AES-GCM encryption
    operation performed with the same key.
    """
    return os.urandom(NONCE_SIZE)


def generate_hmac(
    hmac_key: bytes,
    ciphertext: bytes,
    nonce: bytes,
) -> bytes:
    """
    Generate HMAC-SHA256 over the nonce and ciphertext.

    Including the nonce ensures that modification of either value
    is detected.
    """
    authenticated_data = nonce + ciphertext

    return hmac.new(
        hmac_key,
        authenticated_data,
        hashlib.sha256,
    ).digest()


def verify_hmac(
    hmac_key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    expected_digest: bytes,
) -> None:
    """Verify HMAC-SHA256 using a timing-safe comparison."""
    calculated_digest = generate_hmac(
        hmac_key=hmac_key,
        ciphertext=ciphertext,
        nonce=nonce,
    )

    if not hmac.compare_digest(
        calculated_digest,
        expected_digest,
    ):
        raise IntegrityError(
            "Message integrity verification failed. "
            "The encrypted message may have been modified."
        )


def encrypt_message(
    plaintext: str,
    keys: MessageKeys,
) -> EncryptedMessage:
    """Encrypt plaintext using AES-256-GCM and generate HMAC-SHA256."""
    if not plaintext or not plaintext.strip():
        raise ValueError("Plaintext message cannot be empty.")

    plaintext_bytes = plaintext.encode("utf-8")
    nonce = generate_nonce()

    aesgcm = AESGCM(keys.encryption_key)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext_bytes,
        None,
    )

    digest = generate_hmac(
        hmac_key=keys.hmac_key,
        ciphertext=ciphertext,
        nonce=nonce,
    )

    return EncryptedMessage(
        ciphertext=encode_bytes(ciphertext),
        nonce=encode_bytes(nonce),
        hmac_digest=encode_bytes(digest),
    )


def decrypt_message(
    encrypted_message: EncryptedMessage,
    keys: MessageKeys,
) -> str:
    """Verify HMAC before decrypting the AES-GCM ciphertext."""
    ciphertext = decode_bytes(encrypted_message.ciphertext)
    nonce = decode_bytes(encrypted_message.nonce)
    expected_digest = decode_bytes(encrypted_message.hmac_digest)

    verify_hmac(
        hmac_key=keys.hmac_key,
        ciphertext=ciphertext,
        nonce=nonce,
        expected_digest=expected_digest,
    )

    aesgcm = AESGCM(keys.encryption_key)

    try:
        plaintext_bytes = aesgcm.decrypt(
            nonce,
            ciphertext,
            None,
        )
    except InvalidTag as error:
        raise DecryptionError(
            "AES-GCM authentication failed. "
            "The ciphertext, nonce, or key is invalid."
        ) from error

    return plaintext_bytes.decode("utf-8")


def get_master_cipher() -> Fernet:
    """
    Load the application master key from the environment.

    This key protects room and private conversation keys before
    they are stored in the database.
    """
    master_key = os.getenv("APP_MASTER_KEY")

    if not master_key:
        raise KeyProtectionError(
            "APP_MASTER_KEY is missing from the .env file."
        )

    try:
        return Fernet(master_key.encode("utf-8"))
    except Exception as error:
        raise KeyProtectionError(
            "APP_MASTER_KEY is invalid."
        ) from error


def protect_message_keys(keys: MessageKeys) -> str:
    """
    Encrypt the AES and HMAC keys using the application master key.

    The returned value can later be stored in Neon.
    """
    key_bundle = (
        encode_bytes(keys.encryption_key)
        + ":"
        + encode_bytes(keys.hmac_key)
    )

    cipher = get_master_cipher()

    protected_bundle = cipher.encrypt(
        key_bundle.encode("utf-8")
    )

    return protected_bundle.decode("utf-8")


def recover_message_keys(protected_value: str) -> MessageKeys:
    """Decrypt a protected AES/HMAC key bundle."""
    cipher = get_master_cipher()

    try:
        decrypted_bundle = cipher.decrypt(
            protected_value.encode("utf-8")
        ).decode("utf-8")
    except InvalidToken as error:
        raise KeyProtectionError(
            "Stored conversation keys could not be recovered."
        ) from error

    try:
        encryption_key_text, hmac_key_text = decrypted_bundle.split(
            ":",
            maxsplit=1,
        )
    except ValueError as error:
        raise KeyProtectionError(
            "Stored conversation key format is invalid."
        ) from error

    encryption_key = decode_bytes(encryption_key_text)
    hmac_key = decode_bytes(hmac_key_text)

    if len(encryption_key) != AES_KEY_SIZE:
        raise KeyProtectionError(
            "Recovered AES key has an invalid length."
        )

    if len(hmac_key) != HMAC_KEY_SIZE:
        raise KeyProtectionError(
            "Recovered HMAC key has an invalid length."
        )

    return MessageKeys(
        encryption_key=encryption_key,
        hmac_key=hmac_key,
    )
