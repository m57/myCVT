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
import base64
from terminaltables import AsciiTable
from bs4 import BeautifulSoup

version = "v 0.1"

def banner():
	print "\n"
	banner = "ICAgICAgICAgICAgICAgICAgICAgIC5kODg4OGIuIDg4OCAgICAgODg4ODg4ODg4ODg4ODggCiAgICAgICAgICAgICAgICAgICAgIGQ4OFAgIFk4OGI4ODggICAgIDg4OCAgICA4ODggICAgIAogICAgICAgICAgICAgICAgICAgICA4ODggICAgODg4ODg4ICAgICA4ODggICAgODg4ICAgICAKODg4ODhiLmQ4OGIuIDg4OCAgODg4ODg4ICAgICAgIFk4OGIgICBkODhQICAgIDg4OCAgICAgCjg4OCAiODg4ICI4OGI4ODggIDg4ODg4OCAgICAgICAgWTg4YiBkODhQICAgICA4ODggICAgIAo4ODggIDg4OCAgODg4ODg4ICA4ODg4ODggICAgODg4ICBZODhvODhQICAgICAgODg4ICAgICAKODg4ICA4ODggIDg4OFk4OGIgODg4WTg4YiAgZDg4UCAgIFk4ODhQICAgICAgIDg4OCAgICAgCjg4OCAgODg4ICA4ODggIlk4ODg4OCAiWTg4ODhQIiAgICAgWThQICAgICAgICA4ODggICAgIAogICAgICAgICAgICAgICAgICA4ODggICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgIFk4YiBkODhQICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgIlk4OFAiICAgCQkJCSVzCg=="
	print base64.b64decode(banner) % version
	print " " * 25 + "AUTHORS: @_x90__\n" + " " * 34 + "/u/jessikawii"
	print "-" * 53
	print


if (len(sys.argv) < 2):
	banner()
	print "Usage: %s [CHECKPOINT HTML FILE]\n" % sys.argv[0]
	exit(1)

soup=BeautifulSoup(open(sys.argv[1]))
rows=soup.find_all(class_=re.compile("(even|odd)_data_row"))
SEC_POLICY = { "title": "", "columns" : [] , "rules" : [] , "ruleSections" : [] }

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
	## PRINT FOR TESTING
	#print SEC_POLICY["rules"][5]

def do_it(pp):

	table_data = []
	headers = []

	for h in pp["columns"]:
		headers.append(str(h))

	headers.pop(len(headers)-1)
	table_data.append(headers)

	SOURCEKEY	= pp["columns"].index("SOURCE")
	DESTKEY		= pp["columns"].index("DESTINATION")
	SERVICEKEY	= pp["columns"].index("SERVICE")

	for id in pp["ruleSections"]:
		for rule in pp["rules"]:
			if rule[len(rule)-1] == id[1]:
				#print rule
				if u"Any" in rule[SOURCEKEY] or u"Any" in rule[DESTKEY] or u"Any" in rule[SERVICEKEY] or u"Disabled" in rule:
					# ADD CLEANUP TO ANY RULES HERE BEFORE PUSH

					rule.pop(len(rule)-1)
					# pop groupID off which was ours for reference

					result = re.findall(".*(?=\xa0)", rule[len(rule)-1])
					if len(result) > 0:
						rule[len(rule)-1] = unicode(result[0])
					# remove checkpoints shitty characters

					table_data.append(rule)

		if len(table_data) > 1:
			print "===> SECTION: %s <===" % id[0]

			ascii = AsciiTable(table_data)
			ascii.inner_row_border = True

			print ascii.table ## RESET TABLE DATA


			f = open(name+"-myCVT-output.txt", "a")
			f.write("===> SECTION: %s <===\n" % id[0])
			f.write(ascii.table)
			f.close()

			table_data = []
			table_data.append(headers)


if __name__ == "__main__":

	if ".html" in sys.argv[1]:
		name = sys.argv[1].split(".")[0]
	else:
		name = sys.argv[1]

	open(name+"-myCVT-output.txt", "w").close() # nice lil hack here to clear the out file...
	parse_SECPOLICY(soup)
	banner()
	do_it(SEC_POLICY)
