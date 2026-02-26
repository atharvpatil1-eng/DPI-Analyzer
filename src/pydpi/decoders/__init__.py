from .ethernet import EthernetDecoder
from .ip import IPDecoder
from .transport import TransportDecoder
from .dns import DNSDecoder
from .tls import TLSDecoder
from .http import HTTPDecoder

def get_default_decoder_chain():
    """Returns the default chain of decoders for DPI."""
    # Order: Ethernet -> IP -> Transport -> [App Layers]
    # App layers can be branched or chained. For simplicity, we'll chain them.
    dns = DNSDecoder()
    tls = TLSDecoder(dns)
    http = HTTPDecoder(tls)
    transport = TransportDecoder(http)
    ip = IPDecoder(transport)
    ethernet = EthernetDecoder(ip)
    return ethernet
