from geoip2.errors import AddressNotFoundError
from colorama import Fore,Style,init
from datetime import datetime
import geoip2.database,os
from scapy.all import *
r=random

###############################################################
BLACKLIST={'1.2.3.4'}
GTA_SUN_SRV='185.56.65.'
MY_IP='192.168.2.123'

FRIENDS={'4.5.6.7':'TEST'}

IP_TXT='ip_database.txt'
KNOWN_IP_ADDR=set()
LST=[]
td=0

##save new IP's into ip_database.txt if true
ADD_NEW_HOSTS_IN_TXT=True

if os.path.exists(IP_TXT):
	with open(IP_TXT,'r',encoding='utf-8') as f:
		for line in f:
			s=line.strip()
			if s:
				KNOWN_IP_ADDR.add(s)

UKN='NONE'
def check_geo_ip(atv):
	if not (os.path.exists('db/city.mmdb') or os.path.exists('db/country.mmdb') or os.path.exists('db/isp.mmdb')):
		return Fore.LIGHTBLACK_EX+'NO GEO INFORMATION AVIABLE'
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
	return Fore.LIGHTBLACK_EX+f":: COUNTRY={iso_code}/{country_name} :: CITY={city_name} :: ISP={isp} "

def insert_ip(atv):
	with open(IP_TXT,'a',encoding='utf-8') as pk:
		pk.write(atv+'\n')
		pk.flush()

def check_private_ip(atv):
	return any(prf in atv for prf in ('192.168.','10.','172.'))

def output_address(atv,S,D):
	dtf=datetime.now().strftime('%H:%M:%S')
	if GTA_SUN_SRV in atv:
		print(Fore.CYAN+'[INFO] GTA_RELAY_IP :::',f'{atv} :: {S} -> {D} #',dtf,check_geo_ip(atv))
	elif atv in FRIENDS:
		print(Fore.GREEN+'[INFO] FRIEND_IP :::',f'{atv} :: {S} -> {D} #',dtf,check_geo_ip(atv),Fore.GREEN+f'user: {FRIENDS[atv]}')
	elif atv in BLACKLIST:
		print(Fore.RED+'[ALERT] BLACKLIST_IP :::',f'{atv} :: {S} -> {D} #',dtf,check_geo_ip(atv))
	elif check_private_ip(atv):
		print(Fore.BLUE+'[INFO] PRIVATE :::',f'{atv} :: {S} -> {D} #',dtf,check_geo_ip(atv))
	else:
		if atv in KNOWN_IP_ADDR:
			print(Fore.MAGENTA+'[INFO] KNOWN_IP :::',f'{atv} :: {S} -> {D} #',dtf,check_geo_ip(atv))
		else:
			print(Fore.YELLOW+'[INFO] NEW_IP :::',f'{atv} :: {S} -> {D} #',dtf,Fore.GREEN+'[+]',check_geo_ip(atv))
			KNOWN_IP_ADDR.add(atv)
			if ADD_NEW_HOSTS_IN_TXT:
				insert_ip(atv)

print(f'p2p scan.. timeout={td}')
def sni(p):
	if p.haslayer(IP) and p.haslayer(UDP):
		if (6672 in {p[UDP].dport,p[UDP].sport}):
			if p[IP].src != MY_IP:
				atv=str(p[IP].src)
			if p[IP].dst != MY_IP:
				atv=str(p[IP].dst)
			if not atv in LST: ## lst for just 1 entry
				LST.append(atv)
				output_address(atv,p[UDP].sport,p[UDP].dport)
				del atv
sniff(prn=sni,store=0)

print('done.')
input(' ')