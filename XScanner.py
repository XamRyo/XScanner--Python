#!/usr/bin/python3

import nmap

print()
print("  ###          ##           #######          # ###            ##             ##### #     ##         ##### #     ##         ##### ##         ##### /##  ")
print(" /####       ####  /      /       ###      /  /###  /      /####          ######  /#    #### /   ######  /#    #### /   ######  /### /   ######  / ##  ")
print("/   ###      /####/      /         ##     /  /  ###/      /  ###         /#   /  / ##    ###/   /#   /  / ##    ###/   /#   /  / ###/   /#   /  /  ##  ")
print("     ###    /   ##       ##        #     /  ##   ##          /##        /    /  /  ##    # #   /    /  /  ##    # #   /    /  /   ##   /    /  /   ##  ")
print("      ###  /              ###           /  ###              /  ##           /  /    ##   #         /  /    ##   #         /  /             /  /    /   ")
print("       ###/              ## ###        ##   ##              /  ##          ## ##    ##   #        ## ##    ##   #        ## ##            ## ##   /    ")
print("        ###               ### ###      ##   ##             /    ##         ## ##     ##  #        ## ##     ##  #        ## ##            ## ##  /     ")
print("        /###                ### ###    ##   ##             /    ##         ## ##     ##  #        ## ##     ##  #        ## ######        ## ###/      ")
print("       /  ###                 ### /##  ##   ##            /      ##        ## ##      ## #        ## ##      ## #        ## #####         ## ##  ###   ")
print("      /    ###                  #/ /## ##   ##            /########        ## ##      ## #        ## ##      ## #        ## ##            ## ##    ##  ")
print("     /      ###                  #/ ##  ##  ##           /        ##       #  ##       ###        #  ##       ###        #  ##            #  ##    ##  ")
print("    /        ###                  # /    ## #      /     #        ##          /        ###           /        ###           /                /     ##  ")
print("   /          ###   /   /##        /      ###     /     /####      ##     /##/          ##       /##/          ##       /##/         /   /##/      ### ")
print("  /            ####/   /  ########/        ######/     /   ####    ## /  /  #####               /  #####               /  ##########/   /  ####    ##  ")
print(" /              ###   /     #####            ###      /     ##      #/  /     ##               /     ##               /     ######     /    ##     #   ")
print("                      |                               #                 #                      #                      #                #               ")
print("                       \\)                              ##                ##                     ##                     ##               ##              ")
print()

print("[Info] This is a PortScanner to scan diferents open ports on a target IP address. ")
print("  ||   Function on NMAP (network mapper) library for python 3.")
print("  ||   Support my repository and give support to the project.")


ip=input("[+] IP Objetivo ==> ")
nm = nmap.PortScanner()
puertos_abiertos="-p "
results = nm.scan(hosts=ip,arguments="-sT -n -Pn -T4")
count=0
#print (results)
print("\nHost : %s" % ip)
print("State : %s" % nm[ip].state())
for proto in nm[ip].all_protocols():
	print("Protocol : %s" % proto)
	print()
	lport = nm[ip][proto].keys()
	sorted(lport)
	for port in lport:
		print ("port : %s\tstate : %s" % (port, nm[ip][proto][port]["state"]))
		if count==0:
			puertos_abiertos=puertos_abiertos+str(port)
			count=1
		else:
			puertos_abiertos=puertos_abiertos+","+str(port)

print("\nPuertos abiertos: "+ puertos_abiertos +" "+str(ip))
import nmap

ip input("[+] Introduce the IP direction first: ")
nm = nmap.PortScanner()
puertos_abiertos="-p "
results = nm.scan(hosts=ip,arguments="-sT -n -Pn -T4")
count=0
#print (results) + Info of scanner IP...
print("\nHost : %s" % ip)
print("State : %s" % nm[ip].state())
for proto in nm[ip].all_protocols():
	print("Protocol : %s" % proto)
	print()
	lport = nm[ip][proto].keys()
	sorted(lport)
	for port in lport:
		print ("port : %s\tstate : %s" % (port, nm[ip][proto][port]["state"]))
		if count==0:
			puertos_abiertos=puertos_abiertos+str(port)
			count=1
		else:
			puertos_abiertos=puertos_abiertos+","+str(port)

print("\nPuertos abiertos: "+ puertos_abiertos +" "+str(ip))