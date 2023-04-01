import logging
import socket
import threading
import time

logger = logging.getLogger(__name__)


class UdpReceiver():
    def __init__(self, port):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._socket.bind(("", port))

        self._lock = threading.Lock()
        self._public_key_to_ips = {}

        self._thread = threading.Thread(target=self._receive_routine)
        self._thread.start()

    def get_ips_by_public_key(self, public_key, max_seconds_since_last_received_message):
        ips = []
        now = time.time()
        with self._lock:
            self._public_key_to_ips.setdefault(public_key, {})
            for ip, last_message_time in self._public_key_to_ips[public_key].items():
                if now - last_message_time <= max_seconds_since_last_received_message:
                    ips.append(ip)
        return ips

    def _receive_routine(self):
        while True:
            data, (ip, _) = self._socket.recvfrom(1024)
            public_key = data.decode()
            with self._lock:
                self._public_key_to_ips.setdefault(public_key, {})
                self._public_key_to_ips[public_key][ip] = time.time()
