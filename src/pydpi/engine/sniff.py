import multiprocessing
import signal
import sys
from typing import Optional, Callable
from scapy.all import sniff
from pydpi.engine.processor import PacketProcessor

class SniffEngine:
    def __init__(self, interface: Optional[str] = None, bpf_filter: Optional[str] = None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.stop_event = multiprocessing.Event()

    def start(self, callback: Callable):
        """Starts sniffing in the current process."""
        print(f"[*] Starting capture on {self.interface or 'all interfaces'}...")
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=callback,
                stop_filter=lambda x: self.stop_event.is_set(),
                store=0
            )
        except Exception as e:
            print(f"[!] Error: {e}")

    def stop(self):
        self.stop_event.set()
