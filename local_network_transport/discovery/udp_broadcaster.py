import socket
import threading
import time


class UdpBroadcaster:
    def __init__(self, port: int, public_key: str, pause_between_iterations_in_seconds):
        self._port = port
        self._public_key = public_key
        self._pause_between_iterations_in_seconds = pause_between_iterations_in_seconds

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._socket.settimeout(0.2)

        self._thread = threading.Thread(target=self.__broadcast_routine)
        self._thread.start()

    def __broadcast_routine(self):
        while True:
            self._socket.sendto(self._public_key.encode(), ('255.255.255.255', self._port))
            time.sleep(self._pause_between_iterations_in_seconds)
