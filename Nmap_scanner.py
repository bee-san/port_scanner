from __future__ import print_function
from __future__ import division

import nmap
import argparse

file = open("open_ports.txt", 'w')

def nmapScan(tgtHost, tgtPort):
	try:
		nmScan = nmap.PortScanner()
		nmScan.scan(tgtHost, tgtPort)
		state = nmScan[tgtHost]['tcp'][int(tgtPort)]['state']
		msg = ("[*]{1} tcp/{2} {3}".format(tgtHost, tgtPort, state))
		if "filtered" not in msg:
			print("[!!!]{}".format(msg))
			file.write(msg)
		elif "open" in msg:
			file.write("msg")
		else:
			print(msg)
	except (KeyboardInterrupt, SystemExit):
		close()

def main():

	try:
		parser = argparse.ArgumentParser()

		parser.add_argument("-p", '--ports', type=int,
						help="display a square of a given number")
		parser.add_argument("-H", '--host', type=str,
						help="display a square of a given number")
		parser.add_argument("-a", '--all_ports', action='store_true', help='uses all ports')

		args = parser.parse_args()



		tgtHost = args.host

		if args.all_ports:
			for port in range(1, 10000):
				tgtPort = str(port)
				nmapScan(tgtHost, tgtPort)

			close()


		tgtPorts = str(args.ports).split(' ')
		#tgtPorts = str(options.tgtPort).split(', ')

		if (tgtHost == None) | (tgtPorts[0] == None):
			print(parser.usage)
			print("\nYou didn't run any command line arguments!")
			tgtHost = input(str("Enter your target host here: "))
			tgtPorts = input(int("Enter your target ports here: "))
			tgtPort = tgtPorts.split(" ")


		else:
			for tgtPort in tgtPorts:
				nmapScan(tgtHost, tgtPort)
	except (KeyboardInterrupt, SystemExit):
		close()
	close()

def close():
	file.close()
	exit(0)

if __name__ == '__main__':
	main()

