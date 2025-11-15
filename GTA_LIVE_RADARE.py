from datetime import datetime,timedelta
from colorama import Fore,Style,init
import threading,time,os,keyboard
from datetime import datetime
from scapy.all import *

MY_IP=''
SNSRV='185.56.65.'

REFRESH_INTERVAL=.3
PKT_TIMEOUT=10

active_ips={}
REFRESH_ACTIVE=True
def press_keyboard():
	global REFRESH_ACTIVE
	while True:
		key=keyboard.read_key()
		if key == 'p':
			REFRESH_ACTIVE=not REFRESH_ACTIVE
			time.sleep(.3)

inactive_ips={}
def display_loop():
	global REFRESH_ACTIVE
	while True:
		dtf=datetime.now().strftime('%H:%M:%S')
		now=datetime.now()
		to_inactivate=[(ip,dtf) for ip,info in active_ips.items() if (now-info["last"]).total_seconds() > PKT_TIMEOUT]
		for ip in to_inactivate:
			info=active_ips.pop(ip[0])
			inactive_ips[ip]={"last_active": info["last"],"packets_total":info["count"],"moved_at":now}
		if REFRESH_ACTIVE:
			os.system('cls')
			print(Fore.WHITE+"\n===== ACTIVE IPs ===== PRESS p to stop/start refresh")
			if active_ips:
				sorted_list=sorted(active_ips.items(),key=lambda x: x[1]["count"],reverse=True)
				for ip,info in sorted_list:
					dt=(datetime.now()-info["last"]).total_seconds()
					print(Fore.GREEN+f"IP_ADDR:: {ip[0]} : {ip[1]}  --> pkts={info['count']} :: last={dt:4.1f}s ago"+Fore.WHITE)
			else:
				print("(none)")
			print(Fore.WHITE+"\n===== IDLE IPs =====")
			if inactive_ips:
				sorted_idle=sorted(inactive_ips.items(),key=lambda x: x[1]["moved_at"],reverse=True)
				for ip,info in sorted_idle:
					print(Fore.RED+f"IP_ADDR:: {ip[0][0]} : {ip[0][1]}  --> total_pkts={info['packets_total']}:: timestamp= {ip[1]}")
			else:
				print(Fore.WHITE+"(none)")
		time.sleep(REFRESH_INTERVAL)


def handle(p):
	if p.haslayer(IP) and p.haslayer(UDP):
		if 6672 in {p[UDP].dport,p[UDP].sport}:
			if MY_IP == p[IP].src:
				ip=(p[IP].dst,p[UDP].dport)
				if not SNSRV in ip[0]:
					if ip not in active_ips:
						active_ips[ip]={'count':1,'last':datetime.now()}
					else:
						active_ips[ip]['count']+=1
						active_ips[ip]['last']=datetime.now()

def start():
	threading.Thread(target=press_keyboard,daemon=True).start()
	threading.Thread(target=display_loop,daemon=True).start()
	sniff(prn=handle,store=0)

start()
input('done')
