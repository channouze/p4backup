#!/usr/bin/python3
import sys
from datetime import datetime, timezone, timedelta
import json
from subprocess import Popen, PIPE
from smtplib import SMTP, SMTP_SSL, ssl
from email.message import EmailMessage
import argparse

TICKET_INVALID = "Invalid P4 Ticket"

class p4backup(object):

	def __init__(self):
	
		parser = argparse.ArgumentParser()
		parser.add_argument("-v", "--verify", help="Runs p4 verify", action="store_true")
		parser.add_argument("-c", "--checkpoint", help="Runs p4 checkpoint", action="store_true")
		parser.add_argument("-b", "--backup", help="Runs full backup", action="store_true")
		args = parser.parse_args()
		
		# read config file and set global vars
		print("Init...")
		with open('config.json') as json_data_file:
			cfg = json.load(json_data_file)
		print("Config file loaded.")
		
		self.p4port = cfg['p4port']
		self.p4user = cfg['p4user']
		self.p4password = cfg['p4password']
		self.p4ticket = cfg['p4ticket']
	
		self.p4root = cfg['p4root']
		self.p4dctl = cfg['p4dctl']
		self.p4d = cfg['p4d']
	
		self.backupdir = cfg['p4backupdir']
		self.backupprefix = self.backupdir + cfg['p4backupprefix']
	
		self.motd_verify_file = self.backupdir + 'verify_status'
		self.motd_backup_file = self.backupdir + 'backup_status'
		self.motd_checkpoint_file = self.backupdir + 'checkpoint_status'
		self.log_file = self.backupdir + 'backup.log'

		self.to_addr = cfg['dest_addr']
		self.from_addr = cfg['sender_addr']
		self.sender_password = cfg['sender_password']
		self.smtphost = cfg['smtphost']
		self.smtpport = cfg['smtpport']
		self.smtptls = cfg['smtptls']
	
		self.verr = False
		self.cerr = False
		self.terr = False
		self.vmsg = ''
		self.cmsg = ''
		self.tmsg = ''
	
		self.main(args)
	
	def main(self, args):

		# open log file in append mode. 
		with open(self.log_file, 'a+') as self.lfile:
			if args.verify:
				print("Verifying...")
				self.verify(self.p4port, self.p4user, self.p4password, self.p4ticket, self.lfile)

			if args.checkpoint:
				print("Checkpointing...")
				self.checkpoint(self.p4dctl, self.p4port, self.p4user, self.p4password, self.p4ticket, self.lfile)
	
			if args.backup:
				print("Backuping...")
				self.archive(self.p4d, self.p4root, self.backupprefix, self.motd_backup_file, self.lfile)

			print("Sending e-mail...")
			self.sendmail(self.smtphost, self.smtpport, self.smtptls, self.to_addr, self.from_addr, self.sender_password)

		self.lfile.close()
	
	def login(self, p4port, p4user, p4password, p4ticket):
		if (len(p4ticket) != 0):
			# try to login with a supplied ticket
			output = Popen(["p4 -p " + p4port + " -P " + p4ticket], shell=True, stdout=PIPE, stderr=PIPE)
				
			stdout, stderr = output.communicate()
			
			if (len(stderr) == 0):
				print("User " + p4user + " logged in.\n")
				return p4ticket
			else:
				print("Could not log in with supplied ticket, attempting to generate one...")					
			
		# if we haven't returned at this point, get a login ticket
		output = Popen(["echo " + p4password + "|" + "p4 -p " + p4port + " -u " + p4user + " login " + "-p"], shell=True, stdout=PIPE, stderr=PIPE)
			
		stdout, stderr = output.communicate()
			
		# output.communicate() is a tuple with stdin and stderr:
		# "Enter password:\n
		# p4ticket"
		# We need to isolate the ticket part. 
			
		if (len(stderr) > 0):
			print("Could not log in. Reason:\n" + stderr)
		else:
			return stdout.splitlines(False)[-1]
		
		return TICKET_INVALID
		
	def logout(self, p4port, p4user):
		print("Logging out...")
		output = Popen(["p4 -p " + p4port + " -u " + p4user + " logout"], shell=True, stdout=PIPE, stderr=PIPE)
		
		stdin, stderr = output.communicate()
		
		if (len(stderr) > 0):
			print("ERROR:\n")
			print (stderr)
		else:
			print(stdin)
		
	
	def verify(self, p4port, p4user, p4password, p4ticket, lfile):
	
		# Connect to the Perforce server
		p4ticket = self.login(p4port, p4user, p4password, p4ticket)
		
		if (p4ticket != TICKET_INVALID):
	
			print("Verifying with p4user: " + p4user + " and p4ticket: " + p4ticket +"\n")
			print("Command line is:\n" + "p4 -p " + p4port + " -u " + p4user + " -P " + p4ticket + " verify -q //...")
			verify = Popen(["p4 -p " + p4port + " -u " + p4user + " -P " + p4ticket + " verify -q //..."], stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
			
			self.vmsg, stderr = verify.communicate()
			
			if (len(stderr) != 0):
				self.verr = True
				self.vmsg += stderr + "\n"
		
			if (self.verr):
				self.vmsg = "Verify failed: " + datetime.now(timezone(-timedelta(hours=5), name='EST')).strftime("%Y%m%dT%X%z") + "\n\n" + self.vmsg + "\n\n"
				vfile = open(self.motd_verify_file, 'a+')
				vfile.write(self.vmsg)
				lfile.write(self.vmsg)
				vfile.close()
				print (self.vmsg + '\n')
			else:
				self.vmsg = "Last successful verify: " + datetime.now(timezone(-timedelta(hours=5), name='EST')).strftime("%Y%m%dT%X%z") + "\n"
				vfile = open(self.motd_verify_file, 'w+')
				vfile.write(self.vmsg)
				lfile.write(self.vmsg)
				vfile.close()
		
			self.logout(p4port, p4user)
		
		else:
			print("Could not process p4 verify.")
	
	def checkpoint(self, p4dctl, p4port, p4user, p4password, p4ticket, lfile):
	
		# Connect to the Perforce server
		p4ticket = self.login(p4port, p4user, p4password, p4ticket)
		
		if (p4ticket != TICKET_INVALID):
		
			cstatus = Popen([p4dctl + " checkpoint -a"], stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
		
			self.cmsg, stderr = cstatus.communicate()
			
			if (len(stderr) > 0):
				self.cerr = True
				self.cmsg = "Checkpoint failed: " + datetime.now(timezone(-timedelta(hours=5), name='EST')).strftime("%Y%m%dT%X%z") + "\n\n" + self.cmsg + "\n\n"
				with open(self.motd_checkpoint_file, 'a+') as cfile:
					cfile.write(self.cmsg)
					lfile.write(self.cmsg)
					cfile.close()
				print(self.cmsg + '\n')
			else:
				self.cmsg = "Last successful checkpoint: " + datetime.now(timezone(-timedelta(hours=5), name='EST')).strftime("%Y%m%dT%X%z") + "\n"
				with open(self.motd_checkpoint_file, 'w+') as cfile:
					cfile.write(self.cmsg)
					lfile.write(self.cmsg)
					cfile.close()
			
			self.logout(p4port, p4user)
		else:
			print("Could not process p4 checkpoint.")
	
	def archive(self, p4d, p4root, backupprefix, motd_backup_file, lfile):
	
		# Connect to the Perforce server
		p4ticket = self.login(p4port, p4user, p4password, p4ticket)
	
		tstatus = Popen([p4d + " -r " + p4root + " -c tar zcf \"" + backupprefix + ".`date +%Y%m%d`.tar.gz "+ p4root + " --exclude=" + p4root + "db.*\""], shell=True, stdin=PIPE, stderr=tmsg, universal_newlines=True)
		self.tmsg += stderr.read
		
		if (int(tstatus.stdin) != 0):
			self.terr = True
			self.tmsg = "Backup failed: " + datetime.now(timezone(-timedelta(hours=5), name='EST')).strftime("%Y%m%dT%X%z") + "\n\n" + self.tmsg + "\n\n"
			with open(motd_backup_file, 'a+') as tfile:
				tfile.write(self.tmsg)
				lfile.write(self.tmsg)
				tfile.close()
			print(tmsg)
		else:
			self.tmsg = "Last successful backup: " + datetime.now() + "\n"
			with open(motd_backup_file, 'w+') as tfile:
				tfile.write(self.tmsg)
				lfile.write(self.tmsg)
				tfile.close()

		
	def sendmail(self, smtphost, smtpport, smtptls, to_addr, from_addr, sender_password):
	
		if (len(to_addr) > 3 and '@' in to_addr):
			      
			m = EmailMessage()

			# Header vars
			m['from'] = "Backup Routine <" + from_addr + ">"
			m['to'] = to_addr
			m.set_default_type('text/plain')

			# Backup run mode detection
			subject = "Backup/Verify"
			if (len(self.vmsg) == 0):
				subject = "Backup"
			elif (len(self.cmsg) == 0 or len(self.tmsg) == 0):
				subject = "Verify"

			# SUCCESS or FAILURE
			if ( self.verr or self.cerr or self.terr ):
				subject += " result: FAILURE"
			else:
				subject += " result: SUCCESS"

			# Set subject only once
			m['subject'] = subject

			# Message body
			m.set_content(self.vmsg + self.cmsg + self.tmsg)

			# Send the email		
			if (smtptls):
				context = ssl.create_default_context()
				smtp = SMTP(smtphost, smtpport)
				smtp.ehlo()
				smtp.starttls(context=context)
			else:
				context = ssl.create_default_context()
				smtp = SMTP_SSL(smtphost, smtpport, context=context)
				smtp.ehlo()
			
			smtp.login(from_addr, sender_password)
			smtp.sendmail(m, from_addr=from_addr, to_addrs=to_addr)		  
			smtp.quit()
		else:
			print("destination e-mail is malformed. Check config.\n e-mail supplied was:" + to_addr)
			
p4backup()
