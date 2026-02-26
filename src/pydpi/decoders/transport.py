from scapy.all import TCP, UDP
from pydpi.decoders.base import BaseDecoder
from pydpi.models.packet import PacketInfo

class TransportDecoder(BaseDecoder):
    def decode(self, payload: any, packet_info: PacketInfo) -> PacketInfo:
        if isinstance(payload, TCP):
            packet_info.sport = payload.sport
            packet_info.dport = payload.dport
            packet_info.tcp_flags = str(payload.flags)
            packet_info.protocol = "TCP"
        elif isinstance(payload, UDP):
            packet_info.sport = payload.sport
            packet_info.dport = payload.dport
            packet_info.protocol = "UDP"
        else:
            return packet_info

        if self.next_decoder:
            return self.next_decoder.decode(payload.payload, packet_info)
        return packet_info
