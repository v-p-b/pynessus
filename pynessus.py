# pynessus.py
# Python module to interact with a Nessus 4.x scanner via XMLRPC.
# http://code.google.com/p/pynessus/
#
# Copyright (C) 2010 Dustin Seibel
#
# GNU General Public Licence (GPL)
# 
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA  02111-1307  USA
#
# 2010-08-12:	Initial version
#
import sys
import urllib2
from urlparse import urljoin
import xml.etree.ElementTree as ET
import re
import datetime
import os

# Regex defs
re_unix_timestamp = re.compile('^\d{10}$')
re_unauthorized = re.compile('<title>200 Unauthorized</title>')

TOKEN_FILE = '.nessus_token'

class NessusServer(object):
	def __init__(self, server, port, username, password):
		self.server = server
		self.port = port
		self.username = username
		self.password = password
		self.token = None
		self.base_url = 'https://%s:%s' % (self.server, self.port)

		# If token file exists, use it
		t = get_token_file()
		valid_token = False
		if t:
			# Check to make sure token is still valid
			if self.check_auth(token=t):	
				self.token = t
				valid_token = True

		# If no valid token, get one and store it
		if not valid_token:
			self.login()
			success = create_token_file(self.token)
			# if not success...

	def login(self):
		"""Login to server"""
		# Clear previous login if exists
		if self.token:
			self.logout()

		# Make call to server
		url = urljoin(self.base_url, 'login')
		data = make_args(login=self.username, password=self.password)
		req = urllib2.urlopen(url, data) 
		resp = req.read()

		# Get token and store it
		parsed = get_values_from_xml(resp, ['token'],)
		if 'token' in parsed:
			self.token = parsed['token']
		else:
			return False

	def logout(self):
		"""Logout from server"""
		url = urljoin(self.base_url, 'logout')
		data = make_args(token=self.token)
		req = urllib2.urlopen(url, data) 
		resp = req.read()
		self.token = None

	def check_auth(self, token):
		"""Does a quick check to make sure token is still valid"""
		url = urljoin(self.base_url, 'scan/list')
		data = make_args(token=token)
		req = urllib2.urlopen(url, data) 
		resp = req.read()
		if re_unauthorized.search(resp):
			return False
		else:
			return True

	def get_report(self, uuid):
		"""Retrieves a report."""
		url = urljoin(self.base_url, 'file/report/download')
		data = make_args(token=self.token, report=uuid)
		req = urllib2.urlopen(url, data) 
		resp = req.read()
		if not check_auth(resp):
			print >> sys.stderr, "Unauthorized"
			return None
		return resp

	def launch_scan(self, name, policy_id, target_list):
		"""Launches scan. Returns UUID of scan."""
		# Create HTTP friendly params
		target_str = ','.join(target_list)
		name = name.replace(' ', '%20')

		# Submit to server
		url = urljoin(self.base_url, 'scan/new')
		data = make_args(token=self.token, policy_id=policy_id, target=target_str, scan_name=name)
		req = urllib2.urlopen(url, data) 
		resp = req.read()
		if not check_auth(resp):
			print >> sys.stderr, "Unauthorized"
			return None

		# Get parsed data
		parsed = get_values_from_xml(resp, ['uuid'])
		return parsed['uuid']

	def list_plugins(self):
		"""List plugins"""
		url = urljoin(self.base_url, 'plugins/list')
		data = make_args(token=self.token)
		req = urllib2.urlopen(url, data) 
		resp = req.read()
		if not check_auth(resp):
			print >> sys.stderr, "Unauthorized"
			return None

	def list_policies(self):
		"""List policies"""
		url = urljoin(self.base_url, 'policy/list')
		data = make_args(token=self.token)
		req = urllib2.urlopen(url, data) 
		resp = req.read()
		if not check_auth(resp):
			print >> sys.stderr, "Unauthorized"
			return None

		# Get parsed data
		parsed = get_values_from_xml(resp, ['policyName', 'policyOwner', 'policyComments'], uniq='policyID')
		return parsed

	def list_reports(self):
		"""List reports"""
		url = urljoin(self.base_url, 'report/list')
		data = make_args(token=self.token)
		req = urllib2.urlopen(url, data) 
		resp = req.read()
		if not check_auth(resp):
			print >> sys.stderr, "Unauthorized"
			return None

		# Get parsed data
		parsed = get_values_from_xml(resp, ['name', 'readableName', 'timestamp'], uniq='name')
		return parsed

	def list_scans(self):
		"""List scans"""
		url = urljoin(self.base_url, 'scan/list')
		data = make_args(token=self.token)
		req = urllib2.urlopen(url, data) 
		resp = req.read()
		if not check_auth(resp):
			print >> sys.stderr, "Unauthorized"
			return None

		# Get parsed data
		parsed = get_values_from_xml(resp, ['owner', 'start_time', 'completion_current', 'completion_total'], uniq='uuid')
		return parsed

def check_auth(resp_str):
	"""Checks for an unauthorized message in HTTP response."""
	if re_unauthorized.search(resp_str):
		return False
	else:
		return True

def create_token_file(token, token_file=TOKEN_FILE):
	"""Creates token file"""
	# Write to file
	try:
		fout = open(token_file, 'w')
	except IOError:
		return False
	fout.write(token)
	fout.close()

	# Confirm the file was created and has the right token
	new_token = get_token_file(token_file)
	if new_token != token:
		return False
	else:
		return True

def get_token_file(token_file=TOKEN_FILE):
	"""Checks token from file"""
	if not os.path.isfile(token_file):
		return False
	fin = open(token_file, 'r')
	token = fin.read()
	fin.close()
	return token
		
def convert_date(unix_timestamp):
	"""Converts UNIX timestamp to a datetime object"""
	#try:
	#	return datetime.datetime.fromtimestamp(float(unix_timestamp))
	#except:
	#	return unix_timestamp
	return datetime.datetime.fromtimestamp(float(unix_timestamp))

def get_values_from_xml(xml_string, key_list, uniq=None):
	"""Gets all key/value pairs from XML"""
	xml = ET.fromstring(xml_string)
	d = {}
	for x in xml.getiterator():
		if uniq:
			# If tag is a unique field, start a new dict
			if x.tag == uniq:
				d[x.text] = {}
				k = x.text

			# Store key/value pair if tag is in key list
			if x.tag in key_list:
				# If the tag has the word time and the value is a UNIX timestamp, convert it
				if 'time' in x.tag and re_unix_timestamp.search(x.text):
					d[k][x.tag] = convert_date(x.text)
				else:
					d[k][x.tag] = x.text

		else:
			# Store key/value pair if tag is in key list
			if x.tag in key_list:
				# If the tag has the word time and the value is a UNIX timestamp, convert it
				if 'time' in x.tag and re_unix_timestamp.search(x.text):
					d[x.tag] = convert_date(x.text)
				else:
					d[x.tag] = x.text
	return d

def make_args(**kwargs):
	"""Returns arg list suitable for GET or POST requests"""
	args = []
	for k in kwargs:
		args.append('%s=%s' % (k, str(kwargs[k])))
	return '&'.join(args)

def zerome(string):
	# taken from http://www.codexon.com/posts/clearing-passwords-in-memory-with-python
	# to be used to secure the password in memory
	# find the header size with a dummy string
	temp = "finding offset"
	header = ctypes.string_at(id(temp), sys.getsizeof(temp)).find(temp)
 
	location = id(string) + header
	size = sys.getsizeof(string) - header
 
	# Check platform
	if 'windows' in sys.platform.lower():
		memset = ctypes.cdll.msvcrt.memset
	else:
		# For Linux, use the following. Change the 6 to whatever it is on your computer.
		memset = ctypes.CDLL("libc.so.6").memset
 
	print "Clearing 0x%08x size %i bytes" % (location, size)
 
	memset(location, 0, size)
