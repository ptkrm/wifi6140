#!/usr/bin/python
from selenium import webdriver
import sys
import os

if len(sys.argv) > 1:
	print str(sys.argv[1])
	directory = str(sys.argv[1])
	if (os.path.isdir(directory)):
		if (os.path.isfile(directory+'/BrowserProfile/chrome_debug.log')):
			chrome_options = webdriver.ChromeOptions()
			chrome_options.add_argument('user-data-dir='+directory+'/BrowserProfile')
			chrome = webdriver.Chrome(chrome_options=chrome_options)
		else:
			print 'Wrong directory'
	else:
		print 'Wrong directory'
		exit()
else:
	print "Please add full path to chrome profile folder"
	exit()