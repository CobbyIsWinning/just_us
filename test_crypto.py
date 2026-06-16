from app.crypto_utils import (
    EncryptedMessage,
    IntegrityError,
    decrypt_message,
    encrypt_message,
    generate_message_keys,
    protect_message_keys,
    recover_message_keys,
)


def test_encryption_and_decryption():
    keys = generate_message_keys()

    encrypted = encrypt_message(
        plaintext="This message is confidential.",
        keys=keys,
    )

    decrypted = decrypt_message(
        encrypted_message=encrypted,
        keys=keys,
    )

    assert decrypted == "This message is confidential."

    print("PASS: Message encrypted and decrypted successfully.")
    print(f"Ciphertext: {encrypted.ciphertext}")
    print(f"Nonce: {encrypted.nonce}")
    print(f"HMAC: {encrypted.hmac_digest}")


def test_key_protection():
    original_keys = generate_message_keys()

    protected_value = protect_message_keys(original_keys)

    recovered_keys = recover_message_keys(protected_value)

    assert (
        recovered_keys.encryption_key
        == original_keys.encryption_key
    )

    assert (
        recovered_keys.hmac_key
        == original_keys.hmac_key
    )

    print("PASS: Conversation keys protected and recovered successfully.")
    print(f"Protected key bundle: {protected_value}")


def test_tampering_detection():
    keys = generate_message_keys()

    encrypted = encrypt_message(
        plaintext="Original secure message.",
        keys=keys,
    )

    modified_ciphertext = list(encrypted.ciphertext)

    replacement_character = (
        "A"
        if modified_ciphertext[-2] != "A"
        else "B"
    )

    modified_ciphertext[-2] = replacement_character

    tampered_message = EncryptedMessage(
        ciphertext="".join(modified_ciphertext),
        nonce=encrypted.nonce,
        hmac_digest=encrypted.hmac_digest,
    )

    try:
        decrypt_message(
            encrypted_message=tampered_message,
            keys=keys,
        )
    except IntegrityError as error:
        print("PASS: Message tampering detected.")
        print(f"Detected error: {error}")
        return

    raise AssertionError(
        "FAIL: Modified ciphertext was not detected."
    )


if __name__ == "__main__":
    test_encryption_and_decryption()
    print()

    test_key_protection()
    print()

    test_tampering_detection()
