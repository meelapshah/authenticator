#!/usr/bin/env python2

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
import os.path
import signal
import sqlite3
import struct
import sys
import time

signal.signal(signal.SIGINT, lambda s,f: sys.exit(0))

b32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
bitmap = {}
for i,c in enumerate(b32chars):
  b = bin(i)[2:]
  bitmap[c] = '0' * (5 - len(b)) + b

def base32tohex(b32):
  bits = ''.join([bitmap[c] for c in b32.upper()])
  if len(bits) % 4 != 0:
    bits = bits[:-1 * (len(bits) % 4)]
  return hex(int(bits, 2))[2:-1]
  
def get_hotp_token(secret, intervals_no):
  try:
    key = base64.b32decode(secret, True)
  except:
    # Dropbox's secret is 26 chars instead of 32
    key = unhexlify(base32tohex(secret))
  msg = struct.pack(">Q", intervals_no)
  h = hmac.new(key, msg, hashlib.sha1).digest()
  o = ord(h[19]) & 15
  h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
  return h

def get_totp_token(secret):
  return get_hotp_token(secret, intervals_no=int(time.time())//30)

def main(argv):
  parser = argparse.ArgumentParser('Generate OTP secrets')
  parser.add_argument('sqlite_db')
  parser.add_argument('-o', '--one', default=None)

  args = parser.parse_args(argv)

  if not os.path.exists(args.sqlite_db):
    print 'db file does not exist'
    sys.exit(-1)

  conn = sqlite3.connect(args.sqlite_db)
  cursor = conn.cursor()
  accounts = cursor.execute('select email,secret from accounts').fetchall()
  conn.close()

  if args.one:
    otp = str(get_totp_token(dict(accounts)[args.one]))
    print otp.zfill(6)
    return 0

  while True:
    for email,secret in accounts:
      otp = str(get_totp_token(secret))
      print otp.zfill(6) + ' ' + email
    sec = int(time.time()) % 30
    while sec <= 30:
      sys.stdout.write('\r[{0}{1}] {2} seconds left '.format('#'*sec, ' '*(30-sec), str(30-sec).rjust(2)))
      sys.stdout.flush()
      time.sleep(1)
      sec += 1
    print '\033[{}A\r'.format(len(accounts)),

if __name__ == '__main__':
  main(sys.argv[1:])
