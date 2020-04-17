# p4backup
A small backup script for perforce instances which does not require p4api nor p4dctl.

Supports checkpointing, verifying checkpoints, and archiving the whole depot.

usage: p4backup.py [-h] [-v] [-c] [-b]

optional arguments:

  -h, --help        show this help message and exit  
  -v, --verify      Runs p4 verify  
  -c, --checkpoint  Runs p4 checkpoint  
  -b, --backup      Runs full backup

## Configuration

Edit **config.json** before running the script:

* **p4port**: the Perforce server url to connect to, e.g. ssl:localhost:1666 if you're using SSL.
* **p4user**: any user that has admin permissions/operator role
* **p4password**: matching password
* **p4root**: root folder of the p4 server
* **p4d**: server executable
* **p4backupdir**: directory to where all the backups, checkpoints and journals will be stored. Needs a trailing slash.
* **p4backupprefix**: prefix used for all the backup, checkpoint and journal files.
* **dest_addr**: e-mail recipient for the backup results
* **sender_addr**: e-mail sender for the backup results
* **sender_password**: matching password
* **smtphost**: e-mail SMTP server
* **smtpport**: SMTP port
* **smtptls**: use TLS?
* **gsuite_clientid**: used only for Google Suite e-mail sender addresses. Read the instructions in the oauth2.py file and fill in the details.
* **gsuite_accesstoken**: leave blank if you are not using Google Suite account to send e-mails.
