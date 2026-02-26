import pytest
from pydpi.decoders.tls import TLSDecoder
from pydpi.models.packet import PacketInfo

def test_tls_decoder_sni():
    decoder = TLSDecoder()
    # Mock TLS Client Hello with SNI "example.com"
    # This is a bit complex to hand-craft, so I'll use a simplified version or skip if too hard
    # For now, let's just test the basic dport logic
    info = PacketInfo(length=100, dport=443)
    result = decoder.decode(b"random data", info)
    assert result.app_protocol == "TLS"
    assert result.summary == "TLS Traffic"

def test_tls_decoder_sni_real_ish():
    decoder = TLSDecoder()
    # A very basic representation of a TLS Client Hello with SNI example.com
    # Header: 16 03 01 ... 01 (Client Hello)
    data = bytearray([0x16, 0x03, 0x01, 0x00, 0x2b, 0x01, 0x00, 0x00, 0x27, 0x03, 0x03])
    data += b"\x00" * 32 # Random
    data += b"\x00" # Session ID len
    data += b"\x00\x02\x00\x2f" # Ciphers
    data += b"\x01\x00" # Compression
    data += b"\x00\x0c" # Extensions len
    data += b"\x00\x00" # Ext type SNI
    data += b"\x00\x08" # Ext len
    data += b"\x00\x06\x00\x00\x03\x61\x62\x63" # SNI list len 6, type 0, len 3, "abc"

    info = PacketInfo(length=len(data))
    result = decoder.decode(data, info)
    assert result.app_protocol == "TLS"
    assert result.payload_info["sni"] == "abc"
