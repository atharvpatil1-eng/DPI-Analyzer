from typing import Dict, Optional
from pydpi.models.packet import PacketInfo
from pydpi.models.flow import Flow

class FlowManager:
    def __init__(self):
        self.flows: Dict[tuple, Flow] = {}

    def update_flow(self, packet: PacketInfo) -> Optional[Flow]:
        key = packet.get_flow_key()
        if not key:
            return None

        if key not in self.flows:
            # Create new flow
            flow = Flow(
                flow_id=str(key),
                src_ip=packet.ip_src,
                dst_ip=packet.ip_dst,
                src_port=packet.sport,
                dst_port=packet.dport,
                protocol=packet.ip_proto
            )
            self.flows[key] = flow

        flow = self.flows[key]
        flow.update(packet)
        return flow

    def get_active_flows(self) -> int:
        return len(self.flows)
