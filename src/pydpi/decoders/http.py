from pydpi.decoders.base import BaseDecoder
from pydpi.models.packet import PacketInfo

class HTTPDecoder(BaseDecoder):
    def decode(self, payload: any, packet_info: PacketInfo) -> PacketInfo:
        data = None
        if hasattr(payload, 'load'):
            data = payload.load
        elif isinstance(payload, bytes):
            data = payload

        if not data:
            return packet_info

        try:
            # Simple check for HTTP methods
            methods = [b"GET ", b"POST ", b"HTTP/1.1", b"HTTP/1.0", b"PUT ", b"DELETE ", b"CONNECT "]
            if any(data.startswith(m) for m in methods):
                packet_info.app_protocol = "HTTP"
                # Extract the first line
                line = data.split(b"\r\n")[0].decode(errors="ignore")
                packet_info.summary = f"HTTP: {line}"
                packet_info.payload_info["http_line"] = line
        except:
            pass

        if self.next_decoder:
            return self.next_decoder.decode(payload, packet_info)
        return packet_info
