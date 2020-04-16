#!/usr/bin/python3
import os, sys
import base64
import json
import argparse
from datetime import datetime, timezone, timedelta
from subprocess import Popen, PIPE
from smtplib import SMTP, SMTP_SSL, ssl
from email.message import EmailMessage
from oauth2 import oauth2

TICKET_INVALID = "Invalid P4 Ticket"

class P4Backup(object):

    def __init__(self):

        self.verr = False
        self.cerr = False
        self.terr = False
        self.vmsg = ''
        self.cmsg = ''
        self.tmsg = ''

    def parse_arguments(self):
        
        parser = argparse.ArgumentParser()
        parser.add_argument("-v", "--verify", help="Runs p4 verify", action="store_true")
        parser.add_argument("-c", "--checkpoint", help="Runs p4 checkpoint", action="store_true")
        parser.add_argument("-b", "--backup", help="Runs full backup", action="store_true")
        
        return parser.parse_args()
    
    def main(self, args):
        
        with open('config.json') as json_data_file:
            cfg = json.load(json_data_file)

        p4port = cfg['p4port']
        p4user = cfg['p4user']
        p4password = cfg['p4password']

        p4root = cfg['p4root']
        p4d = cfg['p4d']

        backupdir = cfg['p4backupdir']
        backupprefix = backupdir + cfg['p4backupprefix']

        motd_verify_file = backupdir + 'verify_status'
        motd_backup_file = backupdir + 'backup_status'
        motd_checkpoint_file = backupdir + 'checkpoint_status'
        log_file = backupdir + 'backup.log'

        to_addr = cfg['dest_addr']
        from_addr = cfg['sender_addr']
        sender_password = cfg['sender_password']
        smtphost = cfg['smtphost']
        smtpport = cfg['smtpport']
        smtptls = cfg['smtptls']

        # Google Suite settings
        clientid = cfg['gsuite_clientid']
        access_token = cfg['gsuite_accesstoken']

        with open(log_file, 'a+') as lfile:
            if args.verify:
                print("Verifying...")
                self.verify(p4port, p4user, p4password, motd_verify_file, lfile)

            if args.checkpoint:
                print("Checkpointing...")
                self.checkpoint(p4port, p4user, p4password, backupprefix, motd_checkpoint_file, lfile)
    
            if args.backup:
                print("Backuping...")
                self.archive(p4d, p4root, backupprefix, motd_backup_file, lfile)

            print("Sending e-mail...")
            self.sendmail(args, smtphost, smtpport, smtptls, to_addr, from_addr, sender_password, clientid, access_token)

        lfile.close()
    
    def login(self, p4port, p4user, p4password):
        
        output = Popen(["echo " + p4password + "|" + "p4 -p " + p4port + " -u " + p4user + " login " + "-p"], shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = output.communicate()
            
        if (len(stderr) > 0):
            print("ERROR: Could not log in. Reason:\n" + stderr)
        else:
            print("User " + p4user + " logged in.")
            return stdout.splitlines(False)[-1].decode()
        
        return TICKET_INVALID
        
    def verify(self, p4port, p4user, p4password, motd_verify_file, lfile):
    
        p4ticket = self.login(p4port, p4user, p4password)
        
        if (p4ticket != TICKET_INVALID):
    
            verify = Popen(["p4 -p " + p4port + " -u " + p4user + " -P " + p4ticket + " verify -q //..."], stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
                        
            self.vmsg, stderr = verify.communicate()
            
            if (len(stderr) > 0):
                print("ERROR:\n" + stderr)
                self.verr = True
                self.vmsg += stderr + "\n"
                self.vmsg = "Verify failed: " + datetime.now(timezone(-timedelta(hours=5), name='EST')).strftime("%Y-%m-%dT%X%z") + "\n\n" + self.vmsg + "\n\n"
                with open(motd_verify_file, 'a+') as vfile:
                    vfile.write(self.vmsg)
                    lfile.write(self.vmsg)
                    vfile.close()
                print (self.vmsg + '\n')
            else:
                self.vmsg = "Last successful verify: " + datetime.now(timezone(-timedelta(hours=5), name='EST')).strftime("%Y-%m-%dT%X%z") + "\n"
                with open(motd_verify_file, 'w+') as vfile:
                    vfile.write(self.vmsg)
                    lfile.write(self.vmsg)
                    vfile.close()
        
        else:
            print("Could not process p4 verify.")
    
    def checkpoint(self, p4port, p4user, p4password, backupprefix, motd_checkpoint_file, lfile):

        p4ticket = self.login(p4port, p4user, p4password)
        
        if (p4ticket != TICKET_INVALID):

            cstatus = Popen(["p4 -p " + p4port + " -u " + p4user + " admin checkpoint -Z " + backupprefix], stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)

            self.cmsg, stderr = cstatus.communicate()
        
            if (len(stderr) > 0):
                print("ERROR:\n" + stderr)
                self.cerr = True
                self.cmsg += stderr
                self.cmsg = "Checkpoint failed: " + datetime.now(timezone(-timedelta(hours=5), name='EST')).strftime("%Y-%m-%dT%X%z") + "\n\n" + self.cmsg + "\n\n"
                with open(motd_checkpoint_file, 'a+') as cfile:
                    cfile.write(self.cmsg)
                    lfile.write(self.cmsg)
                    cfile.close()
                print(self.cmsg + '\n')
            else:
                self.cmsg = "Last successful checkpoint: " + datetime.now(timezone(-timedelta(hours=5), name='EST')).strftime("%Y-%m-%dT%X%z") + "\n"
                with open(motd_checkpoint_file, 'w+') as cfile:
                    cfile.write(self.cmsg)
                    lfile.write(self.cmsg)
                    cfile.close()
    
    def archive(self, p4d, p4root, backupprefix, motd_backup_file, lfile):
    
        tstatus = Popen([p4d + " -r " + p4root + " -c \"tar zcfP " + backupprefix + ".`date +%Y%m%d`.tar.gz --exclude=" + p4root + "db.* " + p4root +"\""], shell=True, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        
        self.tmsg, stderr = tstatus.communicate()
        
        if (len(stderr) > 0):
            print("ERROR:" + stderr)
            self.terr = True
            self.tmsg += stderr
            self.tmsg = "Backup failed: " + datetime.now(timezone(-timedelta(hours=5), name='EST')).strftime("%Y-%m-%dT%X%z") + "\n\n" + self.tmsg + "\n\n"
            with open(motd_backup_file, 'a+') as tfile:
                tfile.write(self.tmsg)
                lfile.write(self.tmsg)
                tfile.close()
        else:
            self.tmsg = "Last successful backup: " + datetime.now(timezone(-timedelta(hours=5), name='EST')).strftime("%Y-%m-%dT%X%z") + "\n"
            with open(motd_backup_file, 'w+') as tfile:
                tfile.write(self.tmsg)
                lfile.write(self.tmsg)
                tfile.close()

        print(self.tmsg)
        
    def sendmail(self, args, smtphost, smtpport, smtptls, to_addr, sender_addr, sender_password, clientid, access_token):
    
        if (len(to_addr) > 3 and '@' in to_addr):
                  
            m = EmailMessage()

            # Header vars
            m['from'] = "Backup Routine <" + sender_addr + ">"
            m['to'] = to_addr
            m.set_default_type('text/plain')

            # Backup run mode detection
            subject = "Unknown operation" 
            if args.backup:
                subject = "Backup"
            if args.verify:
                subject = "Verify"
            if args.checkpoint:
                subject = "Checkpoint"
                
            # SUCCESS or FAILURE including server hostname
            if ( self.verr or self.cerr or self.terr ):
                subject += " result for " + os.uname()[1] + ": FAILURE"
            else:
                subject += " result for " + os.uname()[1] + ": SUCCESS"

            # Set subject only once
            m['subject'] = subject

            # Message body
            m.set_content(self.vmsg + self.cmsg + self.tmsg)

            # Send the email
            if len(access_token) > 0:
                # GSuite or Google Accounts
                o = oauth2()
                access_token = o.get_access_token()
                
                auth_string = 'user=%s\1auth=Bearer %s\1\1' % (sender_addr, access_token)
                auth_string = base64.b64encode(auth_string.encode('ascii')).decode('ascii')
                
                smtp = SMTP(smtphost, 587)
                smtp.ehlo(clientid)
                smtp.starttls()
                smtp.docmd('AUTH', 'XOAUTH2 ' + auth_string)
                

            elif (smtptls):
                # Sending as default + TLS
                context = ssl.create_default_context()
                smtp = SMTP(smtphost, smtpport)
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.login(sender_addr, sender_password)
            else:
                # Sending as default unencrypted
                context = ssl.create_default_context()
                smtp = SMTP_SSL(smtphost, smtpport, context=context)
                smtp.ehlo()
                smtp.login(sender_addr, sender_password)

            smtp.send_message(m, sender_addr, to_addr)
            smtp.quit()
        else:
            print("destination e-mail is malformed. Check config.\n e-mail supplied was:" + to_addr)
            
if __name__ == "__main__":
    p = P4Backup()
    args = p.parse_arguments()
    p.main(args)
