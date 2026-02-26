from pydpi.engine.flow_manager import FlowManager
from pydpi.models.packet import PacketInfo

def test_flow_manager():
    fm = FlowManager()

    p1 = PacketInfo(
        length=100,
        ip_src="10.0.0.1", ip_dst="10.0.0.2",
        sport=12345, dport=80, ip_proto=6
    )

    fm.update_flow(p1)
    assert fm.get_active_flows() == 1

    # Reverse packet should belong to the same flow
    p2 = PacketInfo(
        length=200,
        ip_src="10.0.0.2", ip_dst="10.0.0.1",
        sport=80, dport=12345, ip_proto=6
    )

    flow = fm.update_flow(p2)
    assert fm.get_active_flows() == 1
    assert flow.packet_count == 2
    assert flow.byte_count == 300
