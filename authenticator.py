#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Get the otp database from your Android phone:
adb pull /data/data/com.google.android.apps.authenticator2/databases/databases otp.sqlite

Generate otp from your desktop
./[this file] otp.sqlite

Mostly taken from http://stackoverflow.com/questions/8529265/google-authenticator-implementation-in-python
'''

import argparse
import base64
from binascii import unhexlify
import hashlib
import hmac
import json
import os.path
import signal
import sqlite3
import struct
import sys
from termcolor import colored
import time

b32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
bitmap = {}
for i,c in enumerate(b32chars):
  b = bin(i)[2:]
  bitmap[c] = '0' * (5 - len(b)) + b

def base32tohex(b32):
  bits = ''.join([bitmap[c] for c in b32.upper()])
  if len(bits) % 4 != 0:
    bits = bits[:-1 * (len(bits) % 4)]
  return hex(int(bits, 2))[2:]

def decode_secret(secret):
  try:
    return base64.b32decode(secret, True)
  except:
    pass

  try:
    return base64.b32decode(secret + '=' * (8 - len(secret) % 8), True)
  except:
    pass

  return secret

def get_hotp_token(secret, intervals_no):
  key = decode_secret(secret)
  msg = struct.pack(">Q", intervals_no)
  h = hmac.new(key, msg, hashlib.sha1).digest()
  o = h[19] & 15
  h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
  return h

def get_totp_token(secret):
  try:
    return get_hotp_token(secret, intervals_no=int(time.time())//30)
  except:
    return "error"

def load_accounts(db):
  conn = sqlite3.connect(db)
  cursor = conn.cursor()
  accounts = cursor.execute('select email,secret from accounts').fetchall()
  conn.close()
  return accounts

def main(argv=sys.argv[1:]):
  parser = argparse.ArgumentParser('Generate OTP secrets')
  parser.add_argument('-d', '--dbfile', default=os.path.expanduser('~/encrypted/otp_secrets.sqlite'))
  parser.set_defaults(command='gen', one=None)

  subparser = parser.add_subparsers()
  list_parser = subparser.add_parser('list')
  list_parser.set_defaults(command='list')

  gen_parser = subparser.add_parser('gen')
  gen_parser.set_defaults(command='gen')
  gen_parser.add_argument('-o', '--one', default=None)

  args = parser.parse_args(argv)

  if not os.path.exists(args.dbfile):
    print('db file does not exist')
    sys.exit(-1)

  accounts = load_accounts(args.dbfile)

  if args.command == 'list':
    print(*(a[0] for a in accounts), sep='\n')
    return 0

  if args.command == 'gen':
    if args.one:
      otp = None
      if args.one in dict(accounts):
        otp = str(get_totp_token(dict(accounts)[args.one]))
      else:
        for n, s in accounts:
          if args.one in n.lower():
            otp = str(get_totp_token(s))
      if otp:
        print(otp.zfill(6))
        return 0
      return -1

    signal.signal(signal.SIGINT, lambda s,f: sys.exit(0))

    blocks = [u'', u'▏',u'▎',u'▍',u'▌',u'▋',u'▊',u'▉',u'█']
    while True:
      for email,secret in accounts:
        otp = str(get_totp_token(secret))
        print(otp.zfill(6) + ' ' + email)
      sec = time.time() % 30
      while sec <= 30:
        bar = blocks[-1] * int(sec) + blocks[int(8 * (sec % 1))]
        msg = u'\r{0}{1} {2} seconds left '.format(bar, '.'*(30-len(bar)), str(30-int(sec)).rjust(2))
        if sec <= 25:
          sys.stdout.write(msg)
        else:
          sys.stdout.write(colored(msg, 'red'))
        sys.stdout.flush()
        time.sleep(0.125)
        _sec = time.time() % 30
        if _sec < sec:
          break
        sec = _sec
      print('\033[{}A\r'.format(1+len(accounts)), end=None)

def fx_addon():
  def getMessage():
    rawLength = sys.stdin.buffer.read(4)
    if len(rawLength) == 0:
      sys.exit(0)
    messageLength = struct.unpack('@I', rawLength)[0]
    message = sys.stdin.buffer.read(messageLength).decode('utf-8')
    return json.loads(message)

  def encodeMessage(messageContent):
    encodedContent = json.dumps(messageContent).encode('utf-8')
    encodedLength = struct.pack('@I', len(encodedContent))
    return {'length': encodedLength, 'content': encodedContent}

  def sendMessage(encodedMessage):
    sys.stdout.buffer.write(encodedMessage['length'])
    sys.stdout.buffer.write(encodedMessage['content'])
    sys.stdout.buffer.flush()

  accounts = load_accounts(os.path.expanduser('~/encrypted/otp_secrets.sqlite'))
  while True:
    receivedMessage = getMessage()
    if receivedMessage == "list":
      sendMessage(encodeMessage([a[0] for a in accounts]))
    elif receivedMessage.startswith("gen:"):
      otp = str(get_totp_token(dict(accounts)[receivedMessage[4:]]))
      sendMessage(encodeMessage(otp.zfill(6)))
    else:
      pass

if __name__ == '__main__':
  if os.path.split(sys.argv[0])[1] == 'fx-authenticator':
    fx_addon()
  else:
    main(sys.argv[1:])
