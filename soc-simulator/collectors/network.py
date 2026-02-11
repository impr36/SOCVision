from scapy.all import sniff
from utils.normalizer import normalize_event
from shared_queue import event_queue
import threading

def packet_callback(packet):
    norm = normalize_event(packet, "network")
    event_queue.put(norm)

def start_network_capture(interface=None):
    def sniffer():
        sniff(iface=interface, prn=packet_callback, store=False, promisc=True)

    t = threading.Thread(target=sniffer, daemon=True)
    t.start()
    return t