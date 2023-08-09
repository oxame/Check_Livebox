#!/usr/bin/python3.6


import getopt, sys,subprocess, re, os
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

#OID SNMPv2-MIB::sysName.0 
SysName = "SNMPv2-MIB::sysName.0"
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
        ReturnNagios(3,"Error occured: {}".format("Output : {}".format(e.output)))

def snmp_get(ip, community, oid):
    cmd = "snmpget -v2c -c {} {} {}".format(community, ip, oid)
    try:
        output = subprocess.check_output(cmd, shell=True)
        return output.decode()
    except subprocess.CalledProcessError as e:
        ReturnNagios(3,"Error occured: {}".format("Output : {}".format(e.output)))

def GetValue(snmpret):
    return snmpret.split('=')[1].split(':')[-1].replace('"','').replace('\n','').replace(' ','')


def GetIndex(snmpret):
    return snmpret.split('=')[0].split('.')[1].replace(' ','')


def CalculBdPass(NewValue, OldValue):
    Out = ""
    for Value in NewValue.keys():
        In = (int(NewValue[Value][2]) - int(OldValue[Value][1])) /1000
        Ou = (int(NewValue[Value][3]) - int(OldValue[Value][2])) /1000 
        Data = "{} - In = {} Ko, Ou = -{} Ko|\nIn={}Ko\nOut=-{}Ko".format(NewValue[Value][1],In,Ou,In,Ou)
        if Out == "":
            Out = "{}".format(Data)
        else:
            Out = "{},{}".format(Out,Data)

    return Out

def TestFile(File):
    return os.path.exists(File)


def CollectValue(ip,community,Desc,Out,In, NewValue):
    
    for Walk in  snmp_walk(ip, community, Desc).split('\n'):
        if Walk:
            NewValue[GetIndex(Walk)] = [GetIndex(Walk), GetValue(Walk), "", ""]
    for Walk in  snmp_walk(ip, community, Out).split('\n'):
        if Walk:
            NewValue[GetIndex(Walk)] = [NewValue[GetIndex(Walk)][0], NewValue[GetIndex(Walk)][1], GetValue(Walk), ""]
    for Walk in  snmp_walk(ip, community, In).split('\n'):
        if Walk:
            NewValue[GetIndex(Walk)] = [NewValue[GetIndex(Walk)][0], NewValue[GetIndex(Walk)][1], NewValue[GetIndex(Walk)][2], GetValue(Walk)]
    return NewValue

def CollectValueName(Name,ip,community,Desc,Out,In, NewValue):
    Index = None
    for Walk in  snmp_walk(ip, community, Desc).split('\n'):
        if Walk:
            if GetValue(Walk) == Name:
                Index = GetIndex(Walk)
                NewValue[GetIndex(Walk)] = [GetIndex(Walk), GetValue(Walk), "", ""]
                break
    if Index == None:
        ReturnNagios(2,"Error interface Name : {} non trouvez".format(Name))
    for Walk in  snmp_walk(ip, community, Out + "." + Index).split('\n'):
        if Walk:
            NewValue[Index] = [NewValue[GetIndex(Walk)][0], NewValue[GetIndex(Walk)][1], GetValue(Walk), ""]
    for Walk in  snmp_walk(ip, community, In + "." + Index).split('\n'):
        if Walk:
            NewValue[Index] = [NewValue[GetIndex(Walk)][0], NewValue[GetIndex(Walk)][1], NewValue[GetIndex(Walk)][2], GetValue(Walk)]
    return NewValue
	
def FileWrite(File,NewValue):
	try:
		with open(File, "w") as text_file:

			for i in NewValue.keys():
				text_file.write("{};{};{};{}\n".format(NewValue[i][0],NewValue[i][1],NewValue[i][2],NewValue[i][3]))
		text_file.close
	except IOError:
		ReturnNagios(2,"Error " + File)

def FileRead(File,OldValue):
	
	if TestFile(File):
		with open(File) as file:
			for line in file:
				OldValue[line.split(';')[0]] = [line.split(';')[1],line.split(';')[2],line.split(';')[3]]
	else:
		ReturnNagios(3,"Fichier : {} erreur".format(File))
	return OldValue

def InterfaceName(Name,ip,community,Desc,Out,In):
    File = "/tmp/{}-{}".format(ip,Name.replace('/','-'))
    OldValue = {}
    NewValue = {}
    if TestFile(File) == False:
        NewValue = CollectValueName(Name,ip,community,Desc,Out,In, NewValue)
        FileWrite(File,NewValue)
        ReturnNagios(3,"Fichier : {} erreur".format(File))
    else:
        OldValue = FileRead(File,OldValue)
        NewValue = CollectValueName(Name,ip,community,Desc,Out,In, NewValue)
        FileWrite(File,NewValue)        
        ReturnNagios(0,CalculBdPass(NewValue, OldValue))

def Interface(ip,community,Desc,Out,In):

    File = "/tmp/{}".format(ip)
    OldValue = {}
    NewValue = {}
    if TestFile(File) == False:
        NewValue = CollectValue(ip,community,Desc,Out,In, NewValue)
        FileWrite(File,NewValue)
        ReturnNagios(3,"Fichier : {} erreur".format(File))
    else:
        OldValue = FileRead(File,OldValue)
        NewValue = CollectValue(ip,community,Desc,Out,In, NewValue)
        FileWrite(File,NewValue)        
        ReturnNagios(1,CalculBdPass(NewValue, OldValue))

def Nominal(ip,community,SysName):
	Sysname = GetValue(snmp_walk(ip,community,SysName))
	if re.search("-n2$|-n$|-nom$|-msn1$",Sysname):
		ReturnNagios(0,"Routeur Nominal : {}".format(Sysname))
	else:
		ReturnNagios(2,"Routeur Secours : {}".format(Sysname))

def Print_Help():
    print("Utilisation: check_livebox.py -i IP -c community -W warning -C critical -s check")
    print("Options:")
    print("-i, --ip		Adresse IP de votre Synology")
    print("-c, --community	Community SNMP de votre Synology")
    print("-W, --warning	Seuil d avertissement en pourcentage")
    print("-C, --critical	Seuil critique en pourcentage")
    print("Exemple: check_livebox.py -i 192.168.1.10 -c public -W 80 -C 90 ")

def ReturnNagios(Exit,Print):
    # Exit Code
    ExitOK = 0
    ExitWarning = 1
    ExitCritical = 2
    ExitUNKNOWN = 3

    if Exit == 0:
        print("OK - {0}".format(Print))
        sys.exit(ExitOK)
    elif Exit == 1:
        print("WARNING - {0}".format(Print))
        sys.exit(ExitWarning)
    elif Exit == 2:
        print("CRITICAL - {0}".format(Print))
        sys.exit(ExitCritical)
    elif Exit == 3:
        print("UNKNOWN - {0}".format(Print))
        sys.exit(ExitUNKNOWN)

def parse_args(argv):
    ip = None
    community = None
    version = None
    warning = 80
    critical = 90
    check = None
    help = False
    Name = None
    try:
        opts, args = getopt.getopt(argv, "i:c:v:V:W:C:s:n:", ["ip=", "community=", "version=", "warning=","critical=", "check=", "Name="])
    except getopt.GetoptError:
        print("check_livebox.py -i <ip> -c <community> -v <version> -u <unit> -s <check>")
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
        elif opt in ("-n", "--name"):
            Name = arg 
        elif opt in ("-h", "--help"):
            help = True                       
    if not (ip and community and version):
            print("check_livebox.py -i <ip> -c <community> -v <version> [-W <warning>] [-C <critical>] [-s <check>] [-n <Name>]")
            sys.exit(2)     
    return ip, community, version, warning, critical, check, Name


def main():

	ip, community, version, warning, critical, check, Name = parse_args(sys.argv[1:])

	if check == "Interface":
		Interface(ip,community,Desc,Out,In)
	if check == "InterfaceName":
		InterfaceName(Name,ip,community,Desc,Out,In)
	if check == 'Nominal':
		Nominal(ip,community,SysName)
	elif help:
		Print_Help()
	else:
		Print_Help()


if __name__ == '__main__':
    main()
