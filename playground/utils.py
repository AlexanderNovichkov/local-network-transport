import requests


def read_key_from_file(path):
    with open(path, "r") as f:
        return f.read()


URL = 'http://localhost:36900'

PRIVATE_KEY_1 = read_key_from_file('playground/private_key_1.pem')
PRIVATE_KEY_2 = read_key_from_file('playground/private_key_2.pem')

PUBLIC_KEY_1 = read_key_from_file('playground/public_key_1.pem')
PUBLIC_KEY_2 = read_key_from_file('playground/public_key_2.pem')


def send_message(receiver_public_key: str,
                 message_data: str,
                 message_seq: int):
    body = {
        'receiver_public_key': receiver_public_key,
        'message_data': message_data,
        'message_seq': message_seq
    }
    response = requests.post(URL + '/send_message', json=body)
    print(response.text, response.status_code)
    return response


def get_messages(sender_public_key: str,
                 last_seq: int):
    body = {
        'sender_public_key': sender_public_key,
        'last_seq': last_seq
    }
    response = requests.post(URL + '/get_messages', json=body)
    print(response.text, response.status_code)
    return response
