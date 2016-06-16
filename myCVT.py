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

version = "v 0.1.5"
verbose = 0
SEC_POLICY = { "title": "", "columns" : [] , "rules" : [] , "ruleSections" : [] }
conf_files = [ "objects.C", "objects.C_41", "objects_5_0.C", "rules.C", "rulebases.fws", "rulebases_5_0.fws" ]

def banner():
	print "\n\033[1;32m"
	banner = "ICAgICAgICAgICAgICAgICAgICAgIC5kODg4OGIuIDg4OCAgICAgODg4ODg4ODg4ODg4ODggCiAgICAgICAgICAgICAgICAgICAgIGQ4OFAgIFk4OGI4ODggICAgIDg4OCAgICA4ODggICAgIAogICAgICAgICAgICAgICAgICAgICA4ODggICAgODg4ODg4ICAgICA4ODggICAgODg4ICAgICAKODg4ODhiLmQ4OGIuIDg4OCAgODg4ODg4ICAgICAgIFk4OGIgICBkODhQICAgIDg4OCAgICAgCjg4OCAiODg4ICI4OGI4ODggIDg4ODg4OCAgICAgICAgWTg4YiBkODhQICAgICA4ODggICAgIAo4ODggIDg4OCAgODg4ODg4ICA4ODg4ODggICAgODg4ICBZODhvODhQICAgICAgODg4ICAgICAKODg4ICA4ODggIDg4OFk4OGIgODg4WTg4YiAgZDg4UCAgIFk4ODhQICAgICAgIDg4OCAgICAgCjg4OCAgODg4ICA4ODggIlk4ODg4OCAiWTg4ODhQIiAgICAgWThQICAgICAgICA4ODggICAgIAogICAgICAgICAgICAgICAgICA4ODggICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgIFk4YiBkODhQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgIlk4OFAiICAgCQkJCSVzCg=="
	print base64.b64decode(banner) % version
	print "\033[0m"
	print " " * 25 + "AUTHORS: @_x90__\n" + " " * 34 + "/u/jessikawii"
	print "-" * 53
	print


def find_configs(fs):
	for root,dirs,files in os.walk(fs):
		if len(files) > 0:
			for f in files:
				for fname in conf_files:
					if fname == f:
						print "%s/%s" % (root,f)


soup=BeautifulSoup(open(sys.argv[1]))
rows=soup.find_all(class_=re.compile("(even|odd)_data_row"))
		
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
		## SET RULE ITEM BACK TO 0
		ruleItem = []

def do_it(pp, filename):

	ids = []
	table_data = []
	headers = []
	no_section = []

	for h in pp["columns"]:
		headers.append(str(h))

	table_data.append(headers)

	SOURCEKEY	= pp["columns"].index("SOURCE")
	DESTKEY		= pp["columns"].index("DESTINATION")
	SERVICEKEY	= pp["columns"].index("SERVICE")

	for id in pp["ruleSections"]:
		ids.append(id[1])

	for id in pp["ruleSections"]:
		for rule in pp["rules"]:
			rule = clean_rule(rule)
			if u"Any" in rule[SOURCEKEY] or u"Any" in rule[DESTKEY] or u"Any" in rule[SERVICEKEY] or u"Disabled" in rule[0]:
				if rule[len(rule)-1] == id[1]:
					table_data.append(rule)
					pp["rules"].remove(rule)
				elif rule[len(rule)-1] not in ids:
					if rule not in no_section:
						no_section.append(rule)
						pp["rules"].remove(rule)
				else:
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
			table_data.append(headers)

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

		write_output(a, "(NO SECTION DEFINED)")
		if (verbose):
			print "--- NO SECTION DEFINED (THESE ARE USUALLY AT THE TOP) ---"
			print s

	print "\033[1;32m[+] Written output to file ./%s\n" % filename

def write_output(filename, table, id):

	f = open(filename+"_myCVT_results.txt", "a")
	f.write("\n--- SECTION: %s ---\n" % id)
	f.write(table)
	f.close()

def clean_td(table_data):
	for rule in table_data:
		if len(rule) > 0:
			rule.pop(len(rule)-1)
	return table_data

def clean_rule(rule):
	# ADD CLEANUP TO ANY RULES HERE BEFORE PUSH
	result = re.findall(u".*(?=\xa0)", rule[len(rule)-2])
	if len(result) > 0:
		rule[len(rule)-2] = unicode(result[0])

	return rule


if __name__ == "__main__":

	if (len(sys.argv) < 2) or "-h" in sys.argv or "--help" in sys.argv:
		banner()
		print "Usage: %s -f [Checkpoint filesystem]" % sys.argv[0]
		print "Usage: %s [CHECKPOINT HTML FILE] [optional args]\n\nOptional Arguments:\n\t-f\tFind Checkpoint Rules in filesystem\n\t-v\tverbose\n" % sys.argv[0]
		exit(1)

	if "-v" in sys.argv:
		verbose += 1

	if "-f" in sys.argv:
		fs = sys.argv[sys.argv.index("-f")+1]
		find_configs(fs)
		exit(1)


	filename = sys.argv[1].split("/").pop()
	parse_SECPOLICY(soup)
	banner()
	do_it(SEC_POLICY, filename)

