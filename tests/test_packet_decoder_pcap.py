from pathlib import Path

from scapy.all import rdpcap

from services.ingestion.packet_decoder import PacketDecoder


def test_decode_demo_pcap():
    pcap_path = (
        Path(__file__).parents[1]
        / "pcap_samples"
        / "demo_attacks.pcap"
    )

    packets = rdpcap(str(pcap_path))
    decoded_packets = [
        PacketDecoder.decode(packet)
        for packet in packets
    ]
    decoded_packets = [
        packet for packet in decoded_packets
        if packet is not None
    ]

    assert len(packets) == 28
    assert len(decoded_packets) == 28

    http_packets = [
        packet for packet in decoded_packets
        if packet.http_data is not None
    ]

    assert len(http_packets) == 14
