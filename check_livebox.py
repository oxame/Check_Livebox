#!/usr/bin/python3.6
# -*- encoding: utf-8 -*-

import getopt, sys,subprocess, re
from datetime import timedelta

# Exit Code
ExitOK = 0
ExitWarning = 1
ExitCritical = 2
ExitUNKNOWN = 3

#OID Description interface
Desc = "IF-MIB::ifDescr"

#OID Out Octet
Out = 'IF-MIB::ifOutOctets'

#OID MIB In Octet
In = 'IF-MIB::ifInOctets'

# Function to convert bytes to GB
def octet_to_gb(bytes):
    return round(int(bytes) / (1024 ** 2), 2)

def GetValue(snmpret):
    return snmpret.split('=')[1].split(':')[-1].replace('"','').replace('\n','')

def snmp_walk(ip, community, oid):
    cmd = "snmpwalk -v 2c -c {} {} {}".format(community, ip, oid)
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output.decode()
    except subprocess.CalledProcessError as e:
        return "Error occured: {}".format(e.output.decode())

def snmp_get(ip, community, oid):
    cmd = "snmpget -v2c -c {} {} {}".format(community, ip, oid)
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output.decode()
    except subprocess.CalledProcessError as e:
        return "Error occured: {}".format(e.output.decode())

def TestFile(File):
	return os.path.exist(File)

def FileWrite(File,ip,community,Desc,Out,In):
	if TestFile(File):
		try:
			with open(File, "a") as text_file:
				for WAlk in snmp_get(ip, community, Desc):
					print(WAlk)
		except IOError:
			ReturnNagios(2,"Error " + File)
	else:
		ReturnNagios(2,"Error " + File)

def FileRead(File):
	if TestFile(File):
		with open(File, "a") as text_file:
			print('hello')
	else:
		print("Hello")

def Interface(ip,community,Desc,Out,In):
	File = "/tmp/" + ip
	FileWrite(File,ip,community,Desc,Out,In)

def Print_Help():
    print("Utilisation: check_livebox.py -i IP -c community -W warning -C critical -s check")
    print("Options:")
    print("-i, --ip		Adresse IP de votre Synology")
    print("-c, --community	Community SNMP de votre Synology")
    print("-W, --warning	Seuil d'avertissement en pourcentage")
    print("-C, --critical	Seuil critique en pourcentage")
    print("-s, --check	Type de vérification à effectuer ()")
    print("Exemple: check_livebox.py -i 192.168.1.10 -c public -W 80 -C 90 ")

def ReturnNagios(Exit,Print):
    # Exit Code
    ExitOK = 0
    ExitWarning = 1
    ExitCritical = 2
    ExitUNKNOWN = 3

    if Exit == 0:
        print("OK : {0}".format(Print))
        sys.exit(ExitOK)
    elif Exit == 1:
        print("WARNING : {0}".format(Print))
        sys.exit(ExitWarning)
    elif Exit == 2:
        print("CRITICAL : {0}".format(Print))
        sys.exit(ExitCritical)
    elif Exit == 3:
        print("UNKNOWN : {0}".format(Print))
        sys.exit(ExitUNKNOWN)

def parse_args(argv):
    ip = None
    community = None
    version = None
    warning = 80
    critical = 90
    check = None
    help = False
    try:
        opts, args = getopt.getopt(argv, "i:c:v:V:W:C:s:", ["ip=", "community=", "version=", "warning=","critical=", "check="])
    except getopt.GetoptError:
        print("check_Synology.py -i <ip> -c <community> -v <version> -V <volume> -u <unit> -s <check>")
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-i", "--ip"):
            ip = arg
        elif opt in ("-c", "--community"):
            community = arg
        elif opt in ("-v", "--version"):
            version = arg
        elif opt in ("-W", "--warning"):
            warning = arg
        elif opt in ("-C", "--critical"):
            critical = arg 
        elif opt in ("-s", "--check"):
            check = arg    
        elif opt in ("-h", "--help"):
            help = True                       
    if not (ip and community and version):
            print("check_Synology.py.py -i <ip> -c <community> -v <version> [-V <volume>] [-W <warning>] [-C <critical>] [-s <check>]")
            sys.exit(2)
    if check == 'volume' and volume is None:
        print("check_Synology.py.py -i <ip> -c <community> -v <version> [-V <volume>] [-W <warning>] [-C <critical>] [-s <check>]")
        sys.exit(2)       
    return ip, community, version, volume, warning, critical, check


def main():

	ip, community, version, volume, warning, critical, check = parse_args(sys.argv[1:])

	if check == 'Interface':
		Interface(ip,community,Desc,Out,In)
	elif help:
		Print_Help()
	else:
		Print_Help()


if __name__ == '__main__':
    main()
