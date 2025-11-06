from geoip2.errors import AddressNotFoundError
from colorama import Fore,Style,init
from datetime import datetime
import geoip2.database,os
from scapy.all import *
r=random

###############################################################
BLACKLIST={'0.0.0.0'}
FRIENDS={'1.2.3.4':'TEST'}
GTA_SUN_SRV='185.56.65.'
MY_IP='192.168.2.123'##my local ip

IP_TXT='ip_database.txt'
KNOWN_IP_ADDR=set()
LST=[]
td=0

##save new IP's into ip_database.txt if true
ADD_NEW_HOSTS_IN_TXT=True
gCOLOR=Fore.LIGHTBLACK_EX

if os.path.exists(IP_TXT):
	with open(IP_TXT,'r',encoding='utf-8') as f:
		for line in f:
			s=line.strip()
			if s:
				KNOWN_IP_ADDR.add(s)

UKN='???'
def check_geo_ip(atv):
	if not (os.path.exists('db/city.mmdb') or os.path.exists('db/country.mmdb') or os.path.exists('db/isp.mmdb')):
		return gCOLOR+'NO GEO INFORMATION AVIABLE'
	try:
		with geoip2.database.Reader('db/country.mmdb') as reader:
			country=reader.country(atv)
			country_name=country.country.name or UKN
			iso_code=country.country.iso_code or UKN
	except AddressNotFoundError:
		country_name,iso_code=UKN,UKN
	try:
		with geoip2.database.Reader('db/isp.mmdb') as reader:
			asn=reader.asn(atv)
			isp=asn.autonomous_system_organization or UKN
	except AddressNotFoundError:
		isp =UKN
	try:
		with geoip2.database.Reader('db/city.mmdb') as reader:
			city =reader.city(atv)
			city_name=city.city.names.get('de') or city.city.name or UKN
	except AddressNotFoundError:
		city_name=UKN
	return gCOLOR+f":: COUNTRY={iso_code}/{country_name} :: CITY={city_name} :: ISP={isp} "

print(f'p2p scan.. timeout={td}')
def sni(p):
	if p.haslayer(IP) and p.haslayer(UDP):
		if (6672 in {p[UDP].dport,p[UDP].sport}):
			if p[IP].src !=MY_IP:
				atv=str(p[IP].src)
			if p[IP].dst !=MY_IP:
				atv=str(p[IP].dst)
			if atv and not atv in LST:
				LST.append(atv)
				dtf=datetime.now().strftime('%H:%M:%S')
				if GTA_SUN_SRV in atv:
					print(Fore.CYAN+'[INFO] GTA_RELAY_IP :::',f'{atv} :: {p[UDP].sport} -> {p[UDP].dport} #',dtf,check_geo_ip(atv))
				else:
					if atv in KNOWN_IP_ADDR:
						print(Fore.MAGENTA+'[INFO] KNOWN_IP :::',f'{atv} :: {p[UDP].sport} -> {p[UDP].dport} #',dtf,check_geo_ip(atv))
					else:
						if ADD_NEW_HOSTS_IN_TXT:
							print(Fore.YELLOW+'[INFO] NEW_IP :::',f'{atv} :: {p[UDP].sport} -> {p[UDP].dport} #',dtf,Fore.GREEN+'[+]',Fore.BLUE+check_geo_ip(atv))
							with open(IP_TXT,'a',encoding='utf-8') as pk:
								pk.write(atv+'\n')
								pk.flush()
						else:
							print(Fore.YELLOW+'[INFO] NEW_IP :::',f'{atv} :: {p[UDP].sport} -> {p[UDP].dport} #',dtf,check_geo_ip(atv))
				if atv in BLACKLIST:
					print(Fore.RED+'[ALERT] BLACKLIST :::',f'{atv} :: {p[UDP].sport} -> {p[UDP].dport} #',dtf,check_geo_ip(atv))
				if atv in FRIENDS:
					print(Fore.GREEN+f'[INFO] FRIEND_IP {FRIENDS[atv]} :::',f'{atv} :: {p[UDP].sport} -> {p[UDP].dport} #',dtf,check_geo_ip(atv))
				del atv,dtf
sniff(prn=sni,store=0)

print('done.')
input(' ')