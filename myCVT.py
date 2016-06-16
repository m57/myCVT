#!/usr/bin/env python
#
#    myCVT - Checkpoint Firewall Ruleset Auditor
#    Copyright (C) 2015 @_x90__ , jessikawii
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#############################################################################

import sys
import re
import os
import base64
from terminaltables import SingleTable
from terminaltables import AsciiTable
from bs4 import BeautifulSoup

version = "v 0.1.8"
verbose = 0
SEC_POLICY = { "title": "", "columns" : [] , "rules" : [] , "ruleSections" : [] }
conf_files = [ "objects.C", "objects.C_41", "objects_5_0.C", "rules.C", "rulebases.fws", "rulebases_5_0.fws" ]

def banner():
	print "\n\033[1;32m"
	banner = "ICAgICAgICAgICAgICAgICAgICAgIC5kODg4OGIuIDg4OCAgICAgODg4ODg4ODg4ODg4ODggCiAgICAgICAgICAgICAgICAgICAgIGQ4OFAgIFk4OGI4ODggICAgIDg4OCAgICA4ODggICAgIAogICAgICAgICAgICAgICAgICAgICA4ODggICAgODg4ODg4ICAgICA4ODggICAgODg4ICAgICAKODg4ODhiLmQ4OGIuIDg4OCAgODg4ODg4ICAgICAgIFk4OGIgICBkODhQICAgIDg4OCAgICAgCjg4OCAiODg4ICI4OGI4ODggIDg4ODg4OCAgICAgICAgWTg4YiBkODhQICAgICA4ODggICAgIAo4ODggIDg4OCAgODg4ODg4ICA4ODg4ODggICAgODg4ICBZODhvODhQICAgICAgODg4ICAgICAKODg4ICA4ODggIDg4OFk4OGIgODg4WTg4YiAgZDg4UCAgIFk4ODhQICAgICAgIDg4OCAgICAgCjg4OCAgODg4ICA4ODggIlk4ODg4OCAiWTg4ODhQIiAgICAgWThQICAgICAgICA4ODggICAgIAogICAgICAgICAgICAgICAgICA4ODggICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgIFk4YiBkODhQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgIlk4OFAiICAgCQkJCSVzCg=="
	print base64.b64decode(banner) % version
	print "\033[0m\t -- https://www.github.com/m57/ --"
	print "\n\t       @_x90__ , @jeszicawii"
	print "-" * 58
	print

def usage():

		print "Usage: %s -f [Checkpoint HTML File] [optional arguments]" % sys.argv[0]
		print "\nOptional Arguments:\n"
		print "\t-s\t\tSearch for Checkpoint object files which can be imported into Nipper. (This cannot be used with '-f')"
		print "\t-v\t\tPrint the results of the findings to the terminal in a table."
		print""


def find_configs(fs):
	for root,dirs,files in os.walk(fs):
		if len(files) > 0:
			for f in files:
				for fname in conf_files:
					if fname == f:
						print "%s/%s" % (root,f)


def parse_SECPOLICY(soup):

	## GET THE TABLE
	tags=soup.find_all("table")
	## GET THE HEADERS OF THE TABLE
	for t in tags[1].find_all(class_=re.compile("header")):
		SEC_POLICY["columns"].append(str(t.contents[0].strip()))
		
	## REMOVE FIRST COLUMN
	SEC_POLICY["columns"].pop(0)

	## APPEND THE GROUP ID
	SEC_POLICY["columns"].append("groupID")

	## FIREWALL TITLE
	for t in tags[1].find_all(class_=re.compile("title")):
		SEC_POLICY["title"] = str(t.contents[0].strip().split(" ")[2])
	## FIREWALL RULES
	rules = tags[1].find_all(class_=re.compile("(even|odd)_data_row"))
	ruleItem = [] 
	## SET THE SECTION COUNT TO 0
	sectionCount = 0
	for rule in rules:
		## FOR EACH RULE IN THE TABLE, FIND ALL THE TDS
		tds=rule.find_all("td")	
		## APPEND THE TDS 
		for td in tds:
			if td.text == u'' or td.text == u'\xa0\r\n\t\t\t\t\t\t\t\t\t\t\t\t':
				ruleItem.append(u'(EMPTY)')
			else:
				item = td.text.replace(u'\n\n',u'')
				ruleItem.append(item.replace("\n", "",1 ))
		## CHECK IF ITS A SECTION
		if (len(ruleItem) == 1):
			## IF YES APPEND TO RULE SECTIONS
			sectionCount += 1
			ruleItem.append(unicode(sectionCount))
			SEC_POLICY["ruleSections"].append(ruleItem)
		else:
			## IF NO APPEND TO RULES
			## APPEND THE SECTION COUNT
			ruleItem.append(unicode(sectionCount))
			SEC_POLICY["rules"].append(ruleItem)

		## SET RULE ITEM BACK TO 

		ruleItem = []

def do_it(pp, filename):

	filename = SEC_POLICY["title"] + "_" + filename + "_myCVT_results.txt"

#	if os.path.exists(filename):
#		c = raw_input("\033[1;33m[?]\033[0m '%s' output file already exists. Do you want to replace it? ([Y]/n) > " % filename).strip()
#		if c == "n" or c == "N":
#			print "\033[1;31m[!] Error\033[0m: Please remove file '%s', or agree to overwrite." % filename
#			exit(1)
#		else:
	open(filename, "w").close()

	ids = []
	table_data = []
	headers = []
	no_section = []

	count = 0
	
	potentially_weak_services = [ 
					"22", 	"ssh", 
					"23", 	"telnet", 
					"80", 	"http",
					"21", 	"ftp",
					"20", 	"ftp",
					"69", 	"tftp",
					"123", 	"ntp",
					"161", 	"snmp",
					"5060", "sip",
					"3389", "remote",
					]					
					 

	for h in pp["columns"]:
		headers.append(str(h))

	table_data.append(headers)

	SOURCEKEY	= pp["columns"].index("SOURCE")
	DESTKEY		= pp["columns"].index("DESTINATION")
	SERVICEKEY	= pp["columns"].index("SERVICE")

	for id in pp["ruleSections"]:
		ids.append(id[1])

#	print pp.keys()
#	print pp["ruleSections"][0]
#	print pp["ruleSections"][0][0]
#	exit(1)

	for id in pp["ruleSections"]:
		print pp["rules"][0]
		print pp["rules"][1]
		for rule in pp["rules"]:
			print rule	
			print pp["rules"][1]
			rule = clean_rule(rule)
		
			if u"Any" in rule[SOURCEKEY] or u"Any" in rule[DESTKEY] or u"Any" in rule[SERVICEKEY] or u"Disabled" in rule[0] or rule[SERVICEKEY] in potentially_weak_services:
				
				if rule[len(rule)-1] == id[1]:
					table_data.append(rule)
					pp["rules"].remove(rule)

				elif rule[len(rule)-1] not in ids:
					if rule not in no_section:
						no_section.append(rule)
						pp["rules"].remove(rule)				
				else:
					# hmmmmmmm so confused
					pass

		if len(table_data) > 1:
			new_table_data = clean_td(table_data)
			
			ascii = AsciiTable(table_data)
			single = SingleTable(table_data)

			ascii.inner_row_border = True
			single.inner_row_border = True

			a = ascii.table
			s = single.table

			write_output(filename, a, id[0])

			if (verbose):
				print "--- SECTION: %s ---" % id[0]
				print s

			table_data = []
			table_data.append(pp['columns'])

	if len(no_section) > 0:
		table_data = []
		headers = []

		for h in pp["columns"]:
			headers.append(str(h))

		table_data.append(headers)

		for rule in no_section:
			table_data.append(rule)

		table_data = clean_td(table_data)

		ascii = AsciiTable(table_data)
		single = SingleTable(table_data)

		single.inner_row_border = True
		ascii.inner_row_border = True

		a = ascii.table
		s = single.table

		write_output(filename, a, "(NO SECTION DEFINED)")

		if (verbose):
			print "--- NO SECTION DEFINED (THESE ARE USUALLY AT THE TOP) ---"
			print s

	print "\033[1;32m[+]\033[0m Written output to file './%s'\n" % filename

	print "\n\033[1;31m[!]\033[0m '%d' potentially dangerous rules identified.\n" % count


def write_output(filename, table, id):

	f = open(filename, "a")
	f.write("\n--- SECTION: %s ---\n" % id)
	f.write(table)
	f.close()

def clean_td(table_data):
	for rule in table_data:
		if (len(rule) > 0) and (not rule == SEC_POLICY["columns"]):
			rule.pop(len(rule)-1)
	return table_data

def clean_rule(rule):
	# ADD CLEANUP TO ANY RULES HERE BEFORE PUSH
	result = re.findall(u".*(?=\xa0)", rule[len(rule)-2])
	if len(result) > 0:
		rule[len(rule)-2] = unicode(result[0])

	return rule

if __name__ == "__main__":

	banner()

	if ("-f" not in sys.argv) or ("-h" in sys.argv) or ("--help" in sys.argv):
		usage()
		exit(1)

	if "-v" in sys.argv:
		verbose += 1

	if "-s" in sys.argv:
		fs = sys.argv[sys.argv.index("-s")+1]
		find_configs(fs)
		exit(1)

	# Get and check file exists
	
	f = sys.argv[sys.argv.index("-f")+1]

	if not os.path.exists(f):
		usage()
		print "\033[1;31m[!] Error:\033[0m Cannot find file '%s'" % f
		exit(1)

	# Parse it with BS4
	print "\033[1;33m[-]\033[0m Parsing the HTML..."
	soup=BeautifulSoup(open(f))
	rows=soup.find_all(class_=re.compile("(even|odd)_data_row"))
	print "\033[1;32m[+]\033[0m Done."

	filename = f.split("/").pop()

	# Parse internally
	print "\033[1;33m[-]\033[0m Searching for interesting rules..."
	parse_SECPOLICY(soup)
	print "\033[1;32m[+]\033[0m Done."
	
	# Profit 
	do_it(SEC_POLICY, filename)

