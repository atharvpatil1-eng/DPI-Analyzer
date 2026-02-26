from abc import ABC, abstractmethod
from typing import Any, Optional
from pydpi.models.packet import PacketInfo

class BaseDecoder(ABC):
    """Base class for all protocol decoders."""

    def __init__(self, next_decoder: Optional['BaseDecoder'] = None):
        self.next_decoder = next_decoder

    @abstractmethod
    def decode(self, raw_packet: Any, packet_info: PacketInfo) -> PacketInfo:
        """
        Decode a packet and update packet_info.
        If next_decoder is set, it should call it.
        """
        pass
