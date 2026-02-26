from pydpi.decoders.base import BaseDecoder
from pydpi.models.packet import PacketInfo

class TLSDecoder(BaseDecoder):
    def decode(self, payload: any, packet_info: PacketInfo) -> PacketInfo:
        data = None
        if hasattr(payload, 'load'):
            data = payload.load
        elif isinstance(payload, bytes) or isinstance(payload, bytearray):
            data = payload

        if not data:
            return packet_info

        # Check for TLS Handshake (0x16), Version 3.x (0x03 0x01/02/03), and Client Hello (0x01)
        # Record Header: Type(1), Version(2), Length(2)
        # Handshake Header: Type(1), Length(3)
        if len(data) > 43 and data[0] == 0x16 and data[1] == 0x03 and data[5] == 0x01:
            packet_info.app_protocol = "TLS"
            try:
                # Basic SNI parser
                # Record Header (5) + Handshake Header (4) + Version (2) + Random (32)
                pos = 5 + 4 + 2 + 32
                if pos >= len(data): return packet_info

                session_id_len = data[pos]
                pos += 1 + session_id_len

                if pos + 2 > len(data): return packet_info
                cipher_suites_len = int.from_bytes(data[pos:pos+2], "big")
                pos += 2 + cipher_suites_len

                if pos >= len(data): return packet_info
                comp_methods_len = data[pos]
                pos += 1 + comp_methods_len

                if pos + 2 <= len(data):
                    extensions_len = int.from_bytes(data[pos:pos+2], "big")
                    pos += 2
                    end_pos = pos + extensions_len

                    while pos + 4 <= end_pos and pos + 4 <= len(data):
                        ext_type = int.from_bytes(data[pos:pos+2], "big")
                        ext_len = int.from_bytes(data[pos+2:pos+4], "big")
                        pos += 4

                        if ext_type == 0: # SNI
                            # SNI list len (2) + type (1) + name len (2)
                            if pos + 5 <= len(data):
                                sni_name_len = int.from_bytes(data[pos+3:pos+5], "big")
                                sni_name = data[pos+5:pos+5+sni_name_len].decode()
                                packet_info.payload_info["sni"] = sni_name
                                packet_info.summary = f"TLS SNI: {sni_name}"
                        pos += ext_len
                if not packet_info.summary:
                    packet_info.summary = "TLS Client Hello"
            except Exception:
                packet_info.summary = "TLS Handshake"
        elif packet_info.dport == 443 or packet_info.sport == 443:
            packet_info.app_protocol = "TLS"
            packet_info.summary = "TLS Traffic"

        if self.next_decoder:
            return self.next_decoder.decode(payload, packet_info)
        return packet_info
