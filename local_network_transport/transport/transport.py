import dataclasses
import json
import logging

import requests

from local_network_transport.crypto import crypto
from local_network_transport.discovery import discovery
from local_network_transport.transport import server
from local_network_transport.transport.message import Message

logger = logging.getLogger(__name__)


class Transport:
    def __init__(self, public_key, private_key, port=37020):
        self._public_key = public_key
        self._private_key = private_key
        self._port = port

        self._discovery = discovery.Discovery(public_key, port)
        self._server = server.Server(public_key, private_key, port)

    def _delivery_message(self, ip: str, message: Message):
        url = f"{ip}:{self._port}/deliver_message"
        logger.debug(f"Call {url} for message {message}")
        requests.post(url=url, json=dataclasses.asdict(message), timeout=1.0)

    def send_message(self, receiver_public_key: str, message_data: str, message_seq: int):
        message = Message(sender_public_key=self._public_key, receiver_public_key=receiver_public_key,
                          data=message_data, seq=message_seq)

        message_bytes = json.dumps(dataclasses.asdict(message)).encode()
        message_bytes_signed_and_encrypted = crypto.sign_and_encrypt(signer_private_key=self._private_key,
                                                                     signer_public_key=self._public_key,
                                                                     encrypt_public_key=receiver_public_key,
                                                                     data=message_bytes)

        receiver_ips = self._discovery.get_ips_by_public_key(receiver_public_key)
        logger.info(f"Sending message to ips: {receiver_ips}")
        for ip in receiver_ips:
            url = f"http://{ip}:{self._port}/deliver_message"
            requests.post(url=url, data=message_bytes_signed_and_encrypted, timeout=0.5)

    def get_messages(self, sender_public_key: str, last_seq: int):
        return self._server.get_messages(sender_public_key, last_seq)
