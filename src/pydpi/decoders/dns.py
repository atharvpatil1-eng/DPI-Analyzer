from scapy.all import DNS, DNSQR
from pydpi.decoders.base import BaseDecoder
from pydpi.models.packet import PacketInfo

class DNSDecoder(BaseDecoder):
    def decode(self, payload: any, packet_info: PacketInfo) -> PacketInfo:
        # Check if it's DNS (usually over UDP 53 or TCP 53)
        # Scapy might have already parsed it if it's well-known port
        dns_layer = None
        if isinstance(payload, DNS):
            dns_layer = payload
        elif hasattr(payload, 'load'):
            # Try to force parse as DNS if we're on port 53
            if packet_info.dport == 53 or packet_info.sport == 53:
                try:
                    dns_layer = DNS(payload.load)
                except:
                    pass

        if dns_layer:
            packet_info.app_protocol = "DNS"
            if dns_layer.qr == 0: # Query
                if dns_layer.qd:
                    qname = dns_layer.qd.qname.decode() if isinstance(dns_layer.qd.qname, bytes) else dns_layer.qd.qname
                    packet_info.payload_info["query"] = qname
                    packet_info.summary = f"DNS Query: {qname}"
            else: # Response
                packet_info.summary = "DNS Response"
                if dns_layer.an:
                    packet_info.payload_info["answers"] = []
                    # Basic extraction of answers
                    pass

        if self.next_decoder:
            return self.next_decoder.decode(payload, packet_info)
        return packet_info
