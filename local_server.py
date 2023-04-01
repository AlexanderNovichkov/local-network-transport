import dataclasses
import http
import logging
import os

from dacite import from_dict
from flask import Flask, request

from local_network_transport.transport.transport import Transport


def _read_key_from_file(path):
    with open(path, "r") as f:
        return f.read()


transport_port = os.environ.get('TRANSPORT_PORT', 37020)
local_server_port = os.environ.get('LOCAL_SERVER_PORT', 36900)

public_key = _read_key_from_file(os.environ.get('PUBLIC_KEY_PATH'))
private_key = _read_key_from_file(os.environ.get('PRIVATE_KEY_PATH'))

transport = Transport(public_key, private_key, transport_port)
app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)


@dataclasses.dataclass
class SendMessageRequest:
    receiver_public_key: str
    message_data: str
    message_seq: int


@dataclasses.dataclass
class GetMessagesRequest:
    sender_public_key: str
    last_seq: int


@app.post("/send_message")
def send():
    try:
        req = from_dict(data_class=SendMessageRequest, data=request.json)
    except Exception as e:
        return str(e), http.HTTPStatus.BAD_REQUEST
    transport.send_message(req.receiver_public_key, req.message_data, req.message_seq)
    return "", http.HTTPStatus.OK


@app.post("/get_messages")
def get():
    try:
        req = from_dict(data_class=GetMessagesRequest, data=request.json)
    except Exception as e:
        return str(e), http.HTTPStatus.BAD_REQUEST
    messages = transport.get_messages(req.sender_public_key, req.last_seq)
    messages_json = list(map(lambda msg: {'data': msg.data, 'seq': msg.seq}, messages))
    return messages_json, http.HTTPStatus.OK


if __name__ == "__main__":
    app.run(host='localhost', port=local_server_port)
