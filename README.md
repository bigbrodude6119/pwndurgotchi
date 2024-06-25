# pwndurgotchi

## A pwnagotchi communication and disruption tool written in python.

Are you tired of pwnagotchi ruining your favorite [Las Vegas convention](https://defcon.org/)? pwndurgotchi can be used to send messages to nearby pwnagotchi and crash different parts of the pwnagotchi software. Tested on the official [pwnagotchi 1.5.5](https://github.com/evilsocket/pwnagotchi) image from evilsocket and a waveshare_2 screen.

## Payloads

### calling_card.json

Send hello with a friendly message to all nearby pwnagotchi. You can change the face, name, and pwn counts. Does not crash any service on the pwnagotchi.

ex: `python pwndurgotchi.py -p ./payloads/calling_card.json -c 10 -v -l 100 -d 2`

### screen_freeze.json

Crash the pwnagotchi screen. Perfect for using right after `calling_card.json`. Doesn't seem to work when using firmware that doesn't display peer faces on the screen.

ex: `python pwndurgotchi.py -p ./payloads/screen_freeze.json -c 10 -v -l 100 -d 1`

### kill_grid.json

Crash the pwngrid service and interrupt the pwnagotchi main loop. Sending this payload out on a loop should prevent the pwnagotchi from sending out deauth packets and the pwnagotchi should no longer be able to communicate with peers. **Must use the -s option**

ex: `python pwndurgotchi.py -p ./payloads/kill_grid.json -c 10 -v -l 100 -d 1 -s`

## Prerequisites

1. A 2.4ghz wifi card in monitor mode (I use airmon-ng to set this up)
2. The Scapy python library

I reccomend using kali linux to get this up and running.

## Help

```
pwndurgotchi 1.0

Usage: python pwndurgotchi.py [-p | --payload <path>] [-i | --interface <name>] [-c | --count <value>]
[-s | static_identity] [-d | --delay <value>] [-l | --loop <value>] [-v | --verbose]

-p --payload            Path to the JSON payload to send
-i --interface          Wireless interface used to send the packets (default wlan0)
-c --count              Number of packets to send at a time (default 1)
-s --static_identity    Use the static identity in each payload
-d --delay              Delay time in between each loop (default 0)
-l --loop               Amount of times to loop (default 0)
-v --verbose            Print logs during execution

Requires a wireless interface in monitor mode and scapy

Payloads:
calling_card.json       Sends a custom face & username to all nearby pwnagotchi
kill_grid.json          Crashes the pwngrid network on all nearby pwnagotchi
screen_freeze.json      Freeze the screen of all nearby pwnagotchi

Made by BigBroDude6119
```

## Misc.

If you find any cool payloads please drop a PR!
