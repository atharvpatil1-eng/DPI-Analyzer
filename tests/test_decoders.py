import pytest
from scapy.all import IP, TCP, Ether, UDP, DNS, DNSQR
from pydpi.decoders.ethernet import EthernetDecoder
from pydpi.decoders.ip import IPDecoder
from pydpi.decoders.transport import TransportDecoder
from pydpi.decoders.dns import DNSDecoder
from pydpi.models.packet import PacketInfo

def test_ethernet_decoder():
    decoder = EthernetDecoder()
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    info = PacketInfo(length=len(pkt))

    result = decoder.decode(pkt, info)
    assert result.eth_src == "00:11:22:33:44:55"
    assert result.eth_dst == "66:77:88:99:aa:bb"

def test_ip_decoder():
    decoder = IPDecoder()
    pkt = IP(src="1.2.3.4", dst="5.6.7.8", proto=6)
    info = PacketInfo(length=len(pkt))

    result = decoder.decode(pkt, info)
    assert result.ip_src == "1.2.3.4"
    assert result.ip_dst == "5.6.7.8"
    assert result.ip_proto == 6

def test_transport_decoder_tcp():
    decoder = TransportDecoder()
    pkt = TCP(sport=1234, dport=80, flags="S")
    info = PacketInfo(length=len(pkt))

    result = decoder.decode(pkt, info)
    assert result.sport == 1234
    assert result.dport == 80
    assert result.protocol == "TCP"
    assert "S" in result.tcp_flags

def test_dns_decoder():
    decoder = DNSDecoder()
    pkt = DNS(qr=0, qd=DNSQR(qname="www.google.com"))
    info = PacketInfo(length=len(pkt), dport=53)

    result = decoder.decode(pkt, info)
    assert result.app_protocol == "DNS"
    assert result.payload_info["query"] == "www.google.com."
