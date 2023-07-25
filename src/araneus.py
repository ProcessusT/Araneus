#!/usr/bin/env python3
#
# Araneus
#
# V 0.1
#
# Made by Proc with love
#
# Author:
#   Processus (@ProcessusT)
#


import os, sys, argparse, random, string, time
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import SMB2_DIALECT_002
from impacket.dcerpc.v5 import transport, lsad
import struct
import binascii
from binascii import hexlify
import dns.resolver
from impacket.examples.smbclient import MiniImpacketShell
import traceback
from datetime import datetime
from impacket.ese import getUnixTime
from ad_ldap import Connect_AD_ldap, Get_AD_computers, SmbScan, Get_online_computers


sys.tracebacklimit = 0


def main():
	print("\n ▄▄▄· ▄▄▄   ▄▄▄·  ▐ ▄ ▄▄▄ .▄• ▄▌.▄▄ · \n▐█ ▀█ ▀▄ █·▐█ ▀█ •█▌▐█▀▄.▀·█▪██▌▐█ ▀. \n▄█▀▀█ ▐▀▀▄ ▄█▀▀█ ▐█▐▐▌▐▀▀▪▄█▌▐█▌▄▀▀▀█▄\n▐█ ▪▐▌▐█•█▌▐█ ▪▐▌██▐█▌▐█▄▄▌▐█▄█▌▐█▄▪▐█\n ▀  ▀ .▀  ▀ ▀  ▀ ▀▀ █▪ ▀▀▀  ▀▀▀  ▀▀▀▀ \n")
	start = time.time()

	parser = argparse.ArgumentParser(add_help = True, description = "Araneus.")

	parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address of DC>')

	auth = parser.add_argument_group('authentication')
	auth.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')

	options = parser.add_argument_group('connection')
	options.add_argument('-dns', action="store", help='DNS server IP address to resolve computers hostname')
	options.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="port", help='Port to connect to SMB Server')
	options.add_argument('-smb2', action="store_true", help='Force the use of SMBv2 protocol')
	options.add_argument('-just-computer', action='store', help='Test only specified computer')
	
	verbosity = parser.add_argument_group('verbosity')
	verbosity.add_argument('-debug', action="store_true", help='Turn DEBUG output ON')
	verbosity.add_argument('-debugmax', action="store_true", help='Turn DEBUG output TO Max')


	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)

	options                             = parser.parse_args()
	domain, username, password, address = parse_target(options.target)
	passLdap 							= password
	if domain is None:
		domain = ''
	if password == '' and username != '' and options.hashes is None :
		from getpass import getpass
		password = getpass("Password:")
		passLdap = password
	if options.hashes is not None:
		lmhash, nthash = options.hashes.split(':')
		if '' == lmhash:
			lmhash = 'aad3b435b51404eeaad3b435b51404ee'
		passLdap       = f"{lmhash}:{nthash}"

	else:
		lmhash = ''
		nthash = ''

	if options.dns is None:
		dns_server = address
	else:
		dns_server = options.dns

	if options.smb2 is True:
		preferredDialect = SMB2_DIALECT_002
	else:
		preferredDialect = None

	debug = options.debug
	debugmax = options.debugmax
	port = int(options.port)

	myNameCharList = string.ascii_lowercase
	myNameLen      = random.randrange(6,12)
	myName         = ''.join((random.choice(myNameCharList) for i in range(myNameLen)))

	# test if account is domain admin by accessing to DC c$ share
	try:
		if options.debug is True or options.debugmax is True:
			print("[+] Testing admin rights...")
		smbClient = SMBConnection(address, address, myName=myName, sess_port=port, preferredDialect=preferredDialect)
		smbClient.login(username, password, domain, lmhash, nthash)
		if smbClient.connectTree("c$") != 1:
			raise
		if options.debug is True or options.debugmax is True:
			print("\t[+] Admin access granted.")
	except:
		print("[!] Error : Account disabled or access denied. Are you really a domain admin ?")
		if options.debug is True or options.debugmax is True:
			import traceback
			traceback.print_exc()
		sys.exit(1)

	# try to connect to ldap
	ldapConnection,baseDN = Connect_AD_ldap(address, domain, username, passLdap, debug, debugmax)

	# catch all computers in domain or just the specified one
	computers_list = Get_AD_computers(ldapConnection, baseDN, options.just_computer, debug, debugmax)
	if debug is True or debugmax is True:
		for komputer in computers_list:
			print(komputer)


	





if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		os._exit(1)
