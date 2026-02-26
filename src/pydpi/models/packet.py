from typing import Any, Dict, Optional, List
from pydantic import BaseModel, Field
from datetime import datetime

class PacketInfo(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    length: int
    interface: Optional[str] = None

    # Layer 2
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None
    eth_type: Optional[int] = None

    # Layer 3
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    ip_proto: Optional[int] = None

    # Layer 4
    sport: Optional[int] = None
    dport: Optional[int] = None
    tcp_flags: Optional[str] = None

    # Layer 7 / DPI Data
    protocol: str = "Unknown"
    app_protocol: Optional[str] = None
    payload_info: Dict[str, Any] = Field(default_factory=dict)
    summary: str = ""

    def get_flow_key(self) -> Optional[tuple]:
        """Returns a 5-tuple (src, dst, sport, dport, proto) for flow tracking."""
        if all([self.ip_src, self.ip_dst, self.ip_proto, self.sport, self.dport]):
            # Sort to ensure bidirectional flows have the same key
            src = (self.ip_src, self.sport)
            dst = (self.ip_dst, self.dport)
            if src > dst:
                return (dst, src, self.ip_proto)
            return (src, dst, self.ip_proto)
        return None
