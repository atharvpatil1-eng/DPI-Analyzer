from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from pydpi.models.packet import PacketInfo

class Flow(BaseModel):
    flow_id: str
    start_time: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)
    packet_count: int = 0
    byte_count: int = 0
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    app_protocol: Optional[str] = None

    def update(self, packet: PacketInfo):
        self.packet_count += 1
        self.byte_count += packet.length
        self.last_seen = packet.timestamp
        if packet.app_protocol:
            self.app_protocol = packet.app_protocol
