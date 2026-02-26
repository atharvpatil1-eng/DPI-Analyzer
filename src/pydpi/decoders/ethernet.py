from scapy.all import Ether, IP, IPv6, TCP, UDP
from pydpi.decoders.base import BaseDecoder
from pydpi.models.packet import PacketInfo

class EthernetDecoder(BaseDecoder):
    def decode(self, raw_packet: Ether, packet_info: PacketInfo) -> PacketInfo:
        if not isinstance(raw_packet, Ether):
            # Try to cast if it's raw bytes, but scapy sniff usually gives Ether objects
            if isinstance(raw_packet, bytes):
                raw_packet = Ether(raw_packet)
            else:
                return packet_info

        packet_info.eth_src = raw_packet.src
        packet_info.eth_dst = raw_packet.dst
        packet_info.eth_type = raw_packet.type

        if self.next_decoder:
            return self.next_decoder.decode(raw_packet.payload, packet_info)
        return packet_info
