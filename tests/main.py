#!/usr/bin/env python
import pam
import unittest
import os
from RestAuthClient import common, restauth_user, group

class TestPAM(unittest.TestCase):
	"""
	Run PAM authentication module unit tests.
	Since PAM works at the system level and this script should ideally be run unprivileged, you will need to
	manually install the PAM module and create some files in /etc/pam.d/.
	
	### SETUP (requires root)

	# as user
	python setup.py testserver # run RestAuth test server with default configuration
	make -f Makefile.plain # build PAM module

	# as root
	make -f Makefile.plain install # install PAM module
	echo "auth requisite pam_restauth.so url=http://[::1]:8000/ service_user=vowi service_password=vowi" > /etc/pam.d/restauth-test
	echo "auth requisite pam_restauth.so url=http://[::1]:8000/ service_user=vowi service_password=vowi group=testgroup" > /etc/pam.d/restauth-test-group
	echo "auth requisite pam_restauth.so url=http://[::1]:8000/ service_user=vowi service_password=vowi group=unknowngroup" > /etc/pam.d/restauth-test-group-unknown
	echo "auth requisite pam_restauth.so url=http://[::1]:8000/ service_user=vowi service_password=vowi [domain=@example.com]" > /etc/pam.d/restauth-test-domain

	### TEARDOWN (requires root)

	# as root
	rm -f /etc/pam.d/restauth-test /etc/pam.d/restauth-test-group /etc/pam.d/restauth-test-group-unknown /etc/pam.d/restauth-test-domain
	"""
	
	def setUp(self):
		for testfile in ["restauth-test", "restauth-test-group", "restauth-test-group-unknown", "restauth-test-domain"]:
			self.assertTrue(os.path.exists("/etc/pam.d/%s" % testfile), """
			Missing PAM service configurations exist in /etc/pam.d/.
			See this test class's documentation for how to create them.
			""")
	
		self.conn = common.RestAuthConnection("http://[::1]:8000", "vowi", "vowi")
		self.user1 = restauth_user.create(self.conn, "user1", "password1")
		self.user2 = restauth_user.create(self.conn, "user2", "password2")
		self.user3 = restauth_user.create(self.conn, "user3", "password3")
		self.group = group.create(self.conn, "testgroup")
		self.group.add_user(self.user1)
	
	def tearDown(self):
		self.group.remove()
		self.user1.remove()
		self.user2.remove()
		self.user3.remove()
	
	def test_user_valid(self):
		self.assertTrue(pam.authenticate(self.user1.name, "password1", "restauth-test"))
		self.assertTrue(pam.authenticate(self.user2.name, "password2", "restauth-test"))
		self.assertTrue(pam.authenticate(self.user3.name, "password3", "restauth-test"))
	
	def test_user_unknown(self):
		self.assertFalse(pam.authenticate("user4", "password4", "restauth-test"))
		
	def test_user_wrong_password(self):
		self.assertFalse(pam.authenticate(self.user1.name, "password0", "restauth-test"))
		self.assertFalse(pam.authenticate(self.user2.name, "password0", "restauth-test"))
		self.assertFalse(pam.authenticate(self.user3.name, "password0", "restauth-test"))
		
	def test_group_valid(self):
		self.assertTrue(pam.authenticate(self.user1.name, "password1", "restauth-test-group"))
		
	def test_group_unknown(self):
		self.assertFalse(pam.authenticate(self.user1.name, "password1", "restauth-test-group-unknown"))
	
	def test_group_not_in_group(self):
		self.assertFalse(pam.authenticate(self.user2.name, "password2", "restauth-test-group"))
		self.assertFalse(pam.authenticate(self.user3.name, "password3", "restauth-test-group"))
	
	def test_group_wrong_password(self):
		self.assertFalse(pam.authenticate(self.user1.name, "password0", "restauth-test-group"))
		
	def test_domain_valid(self):
		self.assertTrue(pam.authenticate("user1@example.com", "password1", "restauth-test-domain"))
		
	def test_domain_wrong_domain(self):
		self.assertFalse(pam.authenticate("user1@wrong.example.com", "password1", "restauth-test-domain"))
		
	def test_domain_no_domain(self):
		self.assertFalse(pam.authenticate(self.user1.name, "password1", "restauth-test-domain"))

if __name__ == '__main__':
	unittest.main()
