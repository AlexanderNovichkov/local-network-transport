import copy
import http
import json
import logging
import threading

from dacite import from_dict
from flask import Flask, request

from local_network_transport.crypto import crypto
from local_network_transport.transport.message import Message

logger = logging.getLogger(__name__)


class Server:
    def __init__(self, public_key: str, private_key:str, port: int):
        self._public_key = public_key
        self._private_key = private_key
        self._port = port

        self._lock = threading.Lock()
        self._sender_public_key_to_received_messages = {}

        self._app = Flask('server')
        self._app.add_url_rule("/deliver_message", methods=['POST'], view_func=self._deliver_message)

        self._thread = threading.Thread(target=self._run)
        self._thread.start()

    def get_messages(self, sender_public_key: str, last_seq: int):
        messages = []
        with self._lock:
            self._sender_public_key_to_received_messages.setdefault(sender_public_key, [])
            for message in self._sender_public_key_to_received_messages[sender_public_key]:
                if message.seq > last_seq:
                    messages.append(message)

        messages = copy.deepcopy(messages)
        messages.sort(key=lambda msg: msg.seq)
        return messages

    def _run(self):
        self._app.run(host='0.0.0.0', port=self._port)

    def _deliver_message(self):
        (message_bytes, signer_public_key) = crypto.decrypt_and_verify(self._private_key, request.data)
        message = from_dict(data_class=Message, data=json.loads(message_bytes))

        if signer_public_key != message.sender_public_key:
            return "message signer is not equal to message sender", http.HTTPStatus.BAD_REQUEST

        if self._public_key != message.receiver_public_key:
            return "receiver public key is not equal to server public key", http.HTTPStatus.BAD_REQUEST

        with self._lock:
            self._sender_public_key_to_received_messages.setdefault(message.sender_public_key, [])
            self._sender_public_key_to_received_messages[message.sender_public_key].append(message)
            logger.debug("Delivered message: " + str(message))

        return "", http.HTTPStatus.OK
