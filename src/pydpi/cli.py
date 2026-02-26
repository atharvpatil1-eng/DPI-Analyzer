import click
import structlog
import sys
from rich.console import Console
from rich.table import Table
from rich.live import Live
from datetime import datetime
from pydpi.engine.sniff import SniffEngine
from pydpi.engine.processor import PacketProcessor
from pydpi.engine.flow_manager import FlowManager
from pydpi.decoders import get_default_decoder_chain
from pydpi.models.packet import PacketInfo

# Setup structured logging
structlog.configure(
    processors=[
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.WriteLoggerFactory(file=open("logs.json", "a")),
)
log = structlog.get_logger()

console = Console()

class LiveDashboard:
    def __init__(self, flow_manager: FlowManager):
        self.packets = []
        self.max_packets = 20
        self.flow_manager = flow_manager

    def add_packet(self, packet: PacketInfo):
        self.packets.append(packet)
        if len(self.packets) > self.max_packets:
            self.packets.pop(0)

        # Update flow tracking
        self.flow_manager.update_flow(packet)

        # Log to file
        log.info("packet_captured", **packet.model_dump(mode="json"))

    def generate_table(self) -> Table:
        active_flows = self.flow_manager.get_active_flows()
        table = Table(title=f"PyDPI Real-time Capture | Active Flows: {active_flows}")
        table.add_column("Timestamp")
        table.add_column("Protocol")
        table.add_column("Source")
        table.add_column("Destination")
        table.add_column("Summary", overflow="fold")

        for p in reversed(self.packets):
            table.add_row(
                p.timestamp.strftime("%H:%M:%S.%f")[:12],
                p.app_protocol or p.protocol,
                f"{p.ip_src or p.eth_src}:{p.sport or ''}",
                f"{p.ip_dst or p.eth_dst}:{p.dport or ''}",
                p.summary
            )
        return table

@click.group()
def cli():
    """PyDPI: Professional Deep Packet Inspection Tool."""
    pass

@cli.command()
@click.option("--interface", "-i", help="Interface to capture on")
@click.option("--filter", "-f", help="BPF filter string")
def capture(interface, filter):
    """Start real-time packet capture and inspection."""
    processor = PacketProcessor(get_default_decoder_chain())
    flow_manager = FlowManager()
    dashboard = LiveDashboard(flow_manager)

    def packet_callback(raw_packet):
        packet_info = processor.process(raw_packet, interface=interface)
        dashboard.add_packet(packet_info)

    engine = SniffEngine(interface=interface, bpf_filter=filter)

    with Live(dashboard.generate_table(), refresh_per_second=4) as live:
        def update_dashboard(raw_packet):
            packet_callback(raw_packet)
            live.update(dashboard.generate_table())

        try:
            engine.start(callback=update_dashboard)
        except KeyboardInterrupt:
            engine.stop()
            console.print("\n[bold red]Stopping capture...[/bold red]")

if __name__ == "__main__":
    cli()
