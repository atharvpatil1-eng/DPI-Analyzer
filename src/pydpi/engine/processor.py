import logging
from typing import List, Any
from pydpi.models.packet import PacketInfo
from pydpi.decoders.base import BaseDecoder

logger = logging.getLogger(__name__)

class PacketProcessor:
    def __init__(self, decoder_chain: BaseDecoder):
        self.decoder_chain = decoder_chain

    def process(self, raw_packet: Any, interface: str = None) -> PacketInfo:
        packet_info = PacketInfo(
            length=len(raw_packet),
            interface=interface
        )

        try:
            packet_info = self.decoder_chain.decode(raw_packet, packet_info)
        except Exception as e:
            # In a real DPI tool, we might want to log this but continue
            pass

        return packet_info
