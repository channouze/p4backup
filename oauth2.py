"""
Adapted from:
https://blog.macuyiko.com/post/2016/how-to-send-html-mails-with-oauth2-and-gmail-in-python.html
https://github.com/google/gmail-oauth2-tools/blob/master/python/oauth2.py
https://developers.google.com/identity/protocols/OAuth2

1. Generate and authorize an OAuth2 (generate_oauth2_token)
2. Generate a new access tokens using a refresh token(refresh_token)
3. Generate an OAuth2 string to use for login (access_token)
"""

import base64
import imaplib
import json
import smtplib
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import lxml.html

GOOGLE_ACCOUNTS_BASE_URL = 'https://accounts.google.com'
REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'

GOOGLE_CLIENT_ID = '<FILL ME IN>'
GOOGLE_CLIENT_SECRET = '<FILL ME IN>'
GOOGLE_REFRESH_TOKEN = None

class oauth2(object):

    def command_to_url(self, command):
        return '%s/%s' % (GOOGLE_ACCOUNTS_BASE_URL, command)


    def url_escape(self, text):
        return urllib.parse.quote(text, safe='~-._')


    def url_unescape(self, text):
        return urllib.parse.unquote(text)


    def url_format_params(self, params):
        param_fragments = []
        for param in sorted(params.items(), key=lambda x: x[0]):
            param_fragments.append('%s=%s' % (param[0], self.url_escape(param[1])))
        return '&'.join(param_fragments)


    def generate_permission_url(self, client_id, scope='https://mail.google.com/'):
        params = {}
        params['client_id'] = client_id
        params['redirect_uri'] = REDIRECT_URI
        params['scope'] = scope
        params['response_type'] = 'code'
        return '%s?%s' % (self.command_to_url('o/oauth2/auth'), self.url_format_params(params))


    def call_authorize_tokens(self, client_id, client_secret, authorization_code):
        params = {}
        params['client_id'] = client_id
        params['client_secret'] = client_secret
        params['code'] = authorization_code
        params['redirect_uri'] = REDIRECT_URI
        params['grant_type'] = 'authorization_code'
        request_url = self.command_to_url('o/oauth2/token')
        response = urllib.request.urlopen(request_url, urllib.parse.urlencode(params).encode('UTF-8')).read().decode('UTF-8')
        return json.loads(response)


    def call_refresh_token(self, client_id, client_secret, refresh_token):
        params = {}
        params['client_id'] = client_id
        params['client_secret'] = client_secret
        params['refresh_token'] = refresh_token
        params['grant_type'] = 'refresh_token'
        request_url = self.command_to_url('o/oauth2/token')
        response = urllib.request.urlopen(request_url, urllib.parse.urlencode(params).encode('UTF-8')).read().decode('UTF-8')
        return json.loads(response)


    def generate_oauth2_string(self, username, access_token, as_base64=False):
        auth_string = 'user=%s\1auth=Bearer %s\1\1' % (username, access_token)
        if as_base64:
            auth_string = base64.b64encode(auth_string.encode('ascii')).decode('ascii')
        return auth_string


    def test_imap(self, user, auth_string):
        imap_conn = imaplib.IMAP4_SSL('imap.gmail.com')
        imap_conn.debug = 4
        imap_conn.authenticate('XOAUTH2', lambda x: auth_string)
        imap_conn.select('INBOX')


    def test_smpt(self, user, base64_auth_string):
        smtp_conn = smtplib.SMTP('smtp.gmail.com', 587)
        smtp_conn.set_debuglevel(True)
        smtp_conn.ehlo('test')
        smtp_conn.starttls()
        smtp_conn.docmd('AUTH', 'XOAUTH2 ' + base64_auth_string)


    def get_authorization(self, google_client_id, google_client_secret):
        scope = "https://mail.google.com/"
        print('Navigate to the following URL to auth:', self.generate_permission_url(google_client_id, scope))
        authorization_code = input('Enter verification code: ')
        response = self.call_authorize_tokens(google_client_id, google_client_secret, authorization_code)
        return response['refresh_token'], response['access_token'], response['expires_in']


    def refresh_authorization(self, google_client_id, google_client_secret, refresh_token):
        response = self.call_refresh_token(google_client_id, google_client_secret, refresh_token)
        return response['access_token'], response['expires_in']


    def send_mail(self, fromaddr, toaddr, subject, message):
        access_token, expires_in = self.refresh_authorization(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN)
        auth_string = self.generate_oauth2_string(fromaddr, access_token, as_base64=True)
        print('access_token:' + access_token + '\n')
        print('expires_in:' + str(expires_in) + '\n')
        print('auth_string:' + auth_string + '\n')

        msg = MIMEMultipart('related')
        msg['Subject'] = subject
        msg['From'] = fromaddr
        msg['To'] = toaddr
        msg.preamble = 'This is a multi-part message in MIME format.'
        msg_alternative = MIMEMultipart('alternative')
        msg.attach(msg_alternative)
        part_text = MIMEText(lxml.html.fromstring(message).text_content().encode('utf-8'), 'plain', _charset='utf-8')
        part_html = MIMEText(message.encode('utf-8'), 'html', _charset='utf-8')
        msg_alternative.attach(part_text)
        msg_alternative.attach(part_html)
        server = smtplib.SMTP('smtp.gmail.com:587')
        server.ehlo(GOOGLE_CLIENT_ID)
        server.starttls()
        server.docmd('AUTH', 'XOAUTH2 ' + auth_string)
        server.sendmail(fromaddr, toaddr, msg.as_string())
        server.quit()
        
    def get_access_token(self):
        access_token, expires_in = self.refresh_authorization(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN)
        
        return access_token
    
    def write_to_config(self, access_token):
                
        with open('config.json', 'r+') as json_config_file:
            cfg = json.load(json_config_file)
            cfg['gsuite_accesstoken'] = access_token
            json_config_file.seek(0)
            json.dump(cfg, json_config_file, sort_keys=True, indent=4)
            json_config_file.truncate()

    if __name__ == '__main__':
        if GOOGLE_REFRESH_TOKEN is None:
            print('No refresh token found, obtaining one')
            refresh_token, access_token, expires_in = self.get_authorization(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
            print('Set the following as your GOOGLE_REFRESH_TOKEN:', refresh_token)
            exit()

        write_to_config(get_access_token())
