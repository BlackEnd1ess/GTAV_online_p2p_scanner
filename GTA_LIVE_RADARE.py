from datetime import datetime
from colorama import Fore,Style,init
from scapy.all import sniff,IP,UDP
import os,keyboard,time,threading

init(autoreset=True)

MY_IP=""
SUN_PREFIX="185.56.65."
GAME_PORT=6672

REFRESH_INTERVAL=.3
PKT_TIMEOUT=15
RECENT_IDLE_TIME=60

REFRESH_ACTIVE=True
hosts={}
lock=threading.Lock()

def clear_screen():
	os.system("cls" if os.name == "nt" else "clear")

def is_ignored_ip(ip):
	if ip == MY_IP:
		return True
	if ip.startswith(SUN_PREFIX):
		return True
	return False

def update_host(ip_key):
	now=datetime.now()
	with lock:
		if ip_key not in hosts:
			hosts[ip_key]={"state": "ACTIVE","visits": 0,"count": 1,"first": now, "last": now, "idle_since": None}
			return
		h=hosts[ip_key]
		if h["state"] != "ACTIVE":
			h["visits"] += 1
			h["state"]="ACTIVE"
		h["count"] += 1
		h["last"]=now

def refresh_states():
	now = datetime.now()
	with lock:
		for info in hosts.values():
			old_state = info["state"]
			silent = (now - info["last"]).total_seconds()
			if silent <= PKT_TIMEOUT:
				info["state"] = "ACTIVE"
				info["idle_since"] = None
			elif silent <= RECENT_IDLE_TIME:
				info["state"] = "IDLE"
				if old_state == "ACTIVE" and info["idle_since"] is None:
					info["idle_since"] = now
			else:
				info["state"] = "DISCONNECTED"

def get_snapshot():
	with lock:
		return list(hosts.items())

def delete_idle_hosts():
	for ip_key in list(hosts.keys()):
		if hosts[ip_key]["state"] == "DISCONNECTED":
			del hosts[ip_key]

def keyboard_loop():
	global REFRESH_ACTIVE
	while True:
		key=keyboard.read_key()
		if key == "p":
			REFRESH_ACTIVE=not REFRESH_ACTIVE
			time.sleep(0.1)
		elif key == "d":
			delete_idle_hosts()
			time.sleep(0.1)

def print_hosts():
	snapshot=get_snapshot()
	shown=[(ip_key,info) for ip_key,info in snapshot if info["state"] != " "]
	shown.sort(key=lambda x: (x[1]["state"] != "ACTIVE",-x[1]["count"],-x[1]["visits"]))
	dtf=datetime.now().strftime("%H:%M:%S")
	clear_screen()
	print(Fore.WHITE + f"\n===== GTA P2P HOST MONITOR ===== timestamp={dtf}")
	print("PRESS p=pause/resume refresh | PRESS d=delete hidden IDLE hosts\n")
	print(Fore.WHITE +f"{'STATE':<14} {'IP':<18} {'PORT':<8} {'PKTS':<8} "
		f"{'VISITS':<8} {'SILENT':<8} {'FIRST_SEEN':<10} "
		f"{'LAST_SEEN':<10} {'IDLE_SINCE'}")
	if not shown:
		print(Fore.WHITE + "(none)")
		return
	now=datetime.now()
	for ip_key, info in shown:
		ip, port = ip_key
		first_seen = info["first"].strftime("%H:%M:%S")
		last_seen = info["last"].strftime("%H:%M:%S")
		silent_for = (now - info["last"]).total_seconds()
		if info["state"] == "ACTIVE":
			silent_text = f"{silent_for:>5.1f}s"
		else:
			silent_text = "     -"
		idle_since = "-"
		if info.get("idle_since"):
			idle_since = info["idle_since"].strftime("%H:%M:%S")
		if info["state"] == "ACTIVE":
			color = Fore.GREEN
		elif info["state"] == "IDLE":
			color = Fore.MAGENTA
		elif info["state"] == "DISCONNECTED":
			color = Fore.RED
		else:
			color = Fore.WHITE
		if info["state"] == "ACTIVE" and silent_for > 3:
			color = Fore.YELLOW
		print(color +
			f"{info['state']:<14} "
			f"{ip:<18} "
			f"{port:<8} "
			f"{info['count']:<8} "
			f"{info['visits']:<8} "
			f"{silent_text:<8} "
			f"{first_seen:<10} "
			f"{last_seen:<10} "
			f"{idle_since}")

def display_loop():
	while True:
		refresh_states()
		if REFRESH_ACTIVE:
			print_hosts()
		time.sleep(REFRESH_INTERVAL)

def get_peer_from_packet(p):
	if not (p.haslayer(IP) and p.haslayer(UDP)):
		return None
	sport=p[UDP].sport
	dport=p[UDP].dport
	if GAME_PORT not in {sport,dport}:
		return None
	src=p[IP].src
	dst=p[IP].dst
	if dst == MY_IP:
		peer_ip=src
		peer_port=sport
	else:
		return None
	if is_ignored_ip(peer_ip):
		return None
	return (peer_ip,peer_port)

def packet_handler(p):
	try:
		peer=get_peer_from_packet(p)
		if peer is not None:
			update_host(peer)
	except Exception as e:
		print(Fore.RED + f"[ERROR] packet_handler: {e}")

def main():
	threading.Thread(target=keyboard_loop,daemon=True).start()
	threading.Thread(target=display_loop,daemon=True).start()
	print("Starting sniff...")
	sniff(prn=packet_handler,store=0,filter=f"udp port {GAME_PORT}")

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("\nStopped.")
