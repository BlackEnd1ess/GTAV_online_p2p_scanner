Project Information: This script is a p2p session scanner for GTA V online and shows you any IP in same session.
it was developed to output as much information as possible about the game's incoming and outgoing UDP packets.

INSTALL INFO!

to execute this script you need to install the latest python3 version.
you can download it on: https://www.python.org/downloads/

as next you need to install these extensions modules!
type in CMD:

pip install scapy
pip install colorama
pip install database
pip install geoip2
-----------------------------------------------------------------------

Make sure the db folder is in the same directory as the script.

UPDATE!! GTA_LIVE_RADARE.py will display active and inactive IP-Addresses by counting Data Packets.
required python modules: 
- keyboard
- threading
- timedelta

install: pip install keyboard

UPDATE 11.02.2026!
- This script now also displays possible free VPNs and standard local home addresses.
- KNOWN_PLAYER_IP to mark already seen IP_ADDR as known (useful to catch annyoing modders)

############################################################################################
if the script is used to detect a modder, the IP address should be added to the Windows firewall and blocked as soon as possible. If you are not the host of the session, you must also block the relay servers by adding the IP address 185.56.65.0/24 to the Windows firewall. 
This is the only legal way to make it as difficult as possible for a modder/crasher to track you and crashing your game.
once the rule is in effect, the modder should be stuck on an endless loading screen, and in the worst case, you'll end up in an empty public session. But at least it's better than constantly having to restart the game or having your game unexpectedly terminated.
