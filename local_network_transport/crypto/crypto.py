import dataclasses
import io
import json
from base64 import b64decode, b64encode

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from dacite import from_dict


def base64_to_bytes(s: str):
    return b64decode(s.encode('utf-8'))


def bytes_to_base64(b: bytes):
    return b64encode(b).decode('utf-8')


def sign(sign_private_key: str, data: bytes) -> bytes:
    key = RSA.import_key(sign_private_key)
    h = SHA256.new(data)
    signature = pss.new(key).sign(h)
    return signature


def verify_signature(signer_public_key: str, data: bytes, signature: bytes):
    key = RSA.import_key(signer_public_key)
    h = SHA256.new(data)
    verifier = pss.new(key)
    verifier.verify(h, signature)


def encrypt(public_key: str, data: bytes) -> bytes:
    public_key = RSA.importKey(public_key)
    session_key = get_random_bytes(16)
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    return enc_session_key + cipher_aes.nonce + tag + ciphertext


def decrypt(private_key: str, data: bytes) -> bytes:
    private_key = RSA.import_key(private_key)
    data_stream = io.BytesIO(data)
    enc_session_key, nonce, tag, ciphertext = [
        data_stream.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)
    ]
    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return data


@dataclasses.dataclass
class _SignedDataStr:
    data_base64: str
    signature_base64: str
    signer_public_key: str


@dataclasses.dataclass
class _SignedData:
    data: bytes
    signature: bytes
    signer_public_key: str


def _signed_data_to_bytes(signed_data: _SignedData):
    signed_data_str = _SignedDataStr(data_base64=bytes_to_base64(signed_data.data),
                                     signature_base64=bytes_to_base64(signed_data.signature),
                                     signer_public_key=signed_data.signer_public_key)
    return json.dumps(dataclasses.asdict(signed_data_str)).encode()


def _bytes_to_signed_data(signed_data_bytes: bytes):
    signed_data_str = from_dict(_SignedDataStr, json.loads(signed_data_bytes.decode()))
    signed_data = _SignedData(data=base64_to_bytes(signed_data_str.data_base64),
                              signature=base64_to_bytes(signed_data_str.signature_base64),
                              signer_public_key=signed_data_str.signer_public_key)
    return signed_data


def sign_and_encrypt(signer_private_key: str, signer_public_key: str, encrypt_public_key: str, data: bytes) -> bytes:
    signature = sign(signer_private_key, data)
    signed_data = _SignedData(data=data, signature=signature,
                              signer_public_key=signer_public_key)
    signed_data_bytes = _signed_data_to_bytes(signed_data)
    return encrypt(encrypt_public_key, signed_data_bytes)


def decrypt_and_verify(encrypt_private_key: str, data: bytes) -> (bytes, str):
    signed_data_bytes = decrypt(encrypt_private_key, data)
    signed_data = _bytes_to_signed_data(signed_data_bytes)
    verify_signature(signed_data.signer_public_key, signed_data.data, signed_data.signature)
    return signed_data.data, signed_data.signer_public_key
