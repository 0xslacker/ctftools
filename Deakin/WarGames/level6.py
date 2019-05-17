#!/usr/bin/python2.7

import string, os, sys
from string import ascii_lowercase, ascii_uppercase, digits
from Crypto.Cipher import AES, DES, DES3
from base64 import b64decode
import hashlib
import subprocess
import binascii

"""
	level6.py - jnunn
	| A quick and dirty script for level 6 in the deakin "wargames"

	# Challenge
	
	We have data encrypted with one of three encryptions (AES, DES, DES3),
	we are also supplied with a list of possible keys which are encoded
	md5 hashes encoded by Ceaser Shift of 6 -> Base64 -> md5 so we can decode
	the first two steps but then we must crack it.
	This script calls on john the ripper to quickly run through rockyou on
	each successful decoded md5hash then testes each found password as a key
	for each of the three ciphers.
	
	Please excuse this code, I know its badly formatted and I could have made
	everything nice into seperate classes. It works so deal with it.
"""

class decryptor(object):

	def __init__(self, key): 
		self.key = key

	def decrypt(self, enc):
		funcs = { 'AES-128-ECB': self.decrypt_aes, 'DES': self.decrypt_des, 'DES3': self.decrypt_des3 }
		for func in funcs.keys():
			print "[*] Trying: "+func
			res = funcs.get(func)(enc)
			if res == None:
				continue
			else:
				print "["+('='*32)+']'
				print "[\t      FOUND\t\t ]"
				print "|\tKey: "+self.key
				print "|\tDecrypted: " + res
				print "|\tMethod: "+func
				print '['+('='*32)+']'
				return res

	def decrypt_aes(self, enc):
		res = None
		try:
			key = self.pad(self.key, 16)
			cipher = AES.new(key[:16], AES.MODE_ECB)
			res = cipher.decrypt(enc)
		except:
			pass
		return res

	def decrypt_des(self, enc):
		res = None
		try:
			key = self.pad(self.key, 8)
			cipher = DES.new(key[:8], DES.MODE_ECB)
			res = cipher.decrypt(enc)
		except:
			pass
		return None

	def decrypt_des3(self, enc):
		res = None
		try:
			key = self.pad(self.key, 8)
			cipher = DES3.new(key[:8], DES3.MODE_ECB)
			res = cipher.decrypt(enc)
		except:
			pass
		return None

	def pad(self, s, padding=16):
		return s + ((padding - (len(s) % padding)) * '\x00')


# The Encrypted password
data = b"\xa3\xfb\xcc\x42\x29\xe9\x43\xd0\xdb\xf5\xc9\x9e\xa5\xbd\x44\x1d"

# Keys from level6 to test
keys = [ 
	"FZW5UJi0UCEfEfWeSpW2FJAcEpK1EfmdEfKcSCW5UJm=",
	"Tfm1TCTpEZKfTfPnFCW5SprnUCLrSsLsEpKcSZKdSfW=",
	"FCE3SMFnTJOcTpifFMTqFZEdSCK1TsAdECLsSfW0SZO=",
	"TMWfTpq2SfG3SJO5UJLpECXsTZGcUMPoSJXqFCS5TfE=" 
]
hashes = []
cracked = []

def shift(s,n=-6):
    lookup = string.maketrans(ascii_lowercase + ascii_uppercase, ascii_lowercase[n:] + ascii_lowercase[:n] + ascii_uppercase[n:] + ascii_uppercase[:n])
    return str(s).translate(lookup)

def check_pot():
	global hashes
	global cracked
	print "[*] Finding cracked hashes"
	with open(os.getenv('HOME') + '/.john/john.pot', 'r') as f:
		for line in f.readlines():
			for h in hashes:
				if (h in line):
					cracked.append(line.split(':')[1].rstrip())

def decode_write(file='hash'):
	global hashes
	if os.path.isfile(file):
		opt = raw_input("[**] File: \""+file+"\" Exists, would you like to overwrite? (y/N): ")
		opt = opt[0] if opt else "N"
		if opt in ('y', 'Y'):
			os.remove(file)
		else:
			with open(file, 'r') as f:
				for h in f.readlines():
					hashes.append(h.rstrip().split(':')[1])
			print "[*] Using file: "+file
			return
	print "[*] Decoding and writing to file..."
	with open(file, 'w+') as f:
		for key in keys:
			h = b64decode(shift(key))
			hashes.append(h)
			f.write('id' + str(keys.index(key)) + ':' + h + "\n")
	print "Wrote: " + str(len(keys)) + " keys to file '"+file+"'"


def call_john(wordlist="/opt/wordlists/rockyou.txt"):
	print "[*] Calling John.."
	with open(os.devnull, 'w') as f:
		john = subprocess.Popen(['/usr/sbin/john', '--format=raw-md5', '--wordlist='+wordlist, 'hash'], stdout=f, stderr=f)
		print "[*] Running John"
		john.wait()
	print "[*] John is done."
	check_pot()


def main(args):
	if len(args) == 0:
		print "error: Please specify a wordlist!\n"
		print "python " + sys.argv[0] + " [wordlist]\n"
		exit(0)
	wordlist = args[0]
	if not os.path.isfile(wordlist):
		print "Error: Please specify a valid wordlist!"
		exit(0)
	decode_write()
	check_pot()
	if not (cracked == []):
		opt = raw_input('[**] We have already cracked some of the hashes, Would you like to try crack the others? (y/N): ')
		opt = opt[0] if opt else "N"
		if opt in ("Y", "y"):
			call_john(wordlist)
		else:
			print "[*] Skipping John"
	else:
		call_john(wordlist)
	print "\n[*] Attempting Decrypt\n"
	decryptor("Pineapple").decrypt(data)
	print "\n[*] FINISHED"

if __name__ == "__main__":
	main(sys.argv[1:])
