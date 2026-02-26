from scapy.all import IP, IPv6
from pydpi.decoders.base import BaseDecoder
from pydpi.models.packet import PacketInfo

class IPDecoder(BaseDecoder):
    def decode(self, payload: any, packet_info: PacketInfo) -> PacketInfo:
        if isinstance(payload, IP):
            packet_info.ip_src = payload.src
            packet_info.ip_dst = payload.dst
            packet_info.ip_proto = payload.proto
            packet_info.protocol = "IPv4"
        elif isinstance(payload, IPv6):
            packet_info.ip_src = payload.src
            packet_info.ip_dst = payload.dst
            packet_info.ip_proto = payload.nh
            packet_info.protocol = "IPv6"
        else:
            return packet_info

        if self.next_decoder:
            return self.next_decoder.decode(payload.payload, packet_info)
        return packet_info
