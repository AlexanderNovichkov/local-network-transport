from local_network_transport.discovery import udp_broadcaster, udp_receiver


class Discovery:
    def __init__(self, public_key: str, port:int, broadcast_pause_in_seconds:float = 1.0):
        self._broadcaster = udp_broadcaster.UdpBroadcaster(port, public_key, broadcast_pause_in_seconds)
        self._receiver = udp_receiver.UdpReceiver(port)

    def get_ips_by_public_key(self, public_key, max_seconds_since_last_received_message=60.0):
        return self._receiver.get_ips_by_public_key(public_key, max_seconds_since_last_received_message)
