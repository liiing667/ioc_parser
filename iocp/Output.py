#!/usr/bin/env python

import os
import sys
import csv
import json

try:
	text_type = unicode
except NameError:
	text_type = str

OUTPUT_FORMATS = ('csv', 'tsv', 'json', 'yara', 'netflow', )

def getHandler(output_format):
	output_format = output_format.lower()
	if output_format not in OUTPUT_FORMATS:
		print("[WARNING] Invalid output format specified... using CSV")
		output_format = 'csv'

	handler_format = "OutputHandler_" + output_format
	handler_class = getattr(sys.modules[__name__], handler_format)

	return handler_class()

class OutputHandler(object):
	def print_match(self, fpath, page, name, match):
		pass

	def print_header(self, fpath):
		pass

	def print_footer(self, fpath):
		pass

	def print_error(self, fpath, exception):
		print("[ERROR] %s" % (exception))

	def print_remote_error(self, fpath, exception):
		category = getattr(exception, 'category', 'remote_error')
		print("[REMOTE ERROR:%s] %s: %s" % (category, fpath, exception))

class OutputHandler_csv(OutputHandler):
	def __init__(self):
		self.csv_writer = csv.writer(sys.stdout)

	def print_match(self, fpath, page, name, match):
		self.csv_writer.writerow((fpath, page, name, match))

	def print_error(self, fpath, exception):
		self.csv_writer.writerow((fpath, '0', 'error', exception))

	def print_remote_error(self, fpath, exception):
		category = getattr(exception, 'category', 'remote_error')
		self.csv_writer.writerow((fpath, '0', category, exception))

class OutputHandler_tsv(OutputHandler):
	def __init__(self):
		self.csv_writer = csv.writer(sys.stdout, delimiter = '\t')

	def print_match(self, fpath, page, name, match):
		self.csv_writer.writerow((fpath, page, name, match))

	def print_error(self, fpath, exception):
		self.csv_writer.writerow((fpath, '0', 'error', exception))

	def print_remote_error(self, fpath, exception):
		category = getattr(exception, 'category', 'remote_error')
		self.csv_writer.writerow((fpath, '0', category, exception))

class OutputHandler_json(OutputHandler):
	def print_match(self, fpath, page, name, match):
		data = {
			'path' : fpath,
			'file' : os.path.basename(fpath),
			'page' : page,
			'type' : name,
			'match': match
		}

		print(json.dumps(data))

	def print_error(self, fpath, exception):
		data = {
			'path'      : fpath,
			'file'      : os.path.basename(fpath),
			'type'      : 'error',
			'exception' : exception
		}

		print(json.dumps(data))

	def print_remote_error(self, fpath, exception):
		data = {
			'path'      : fpath,
			'file'      : os.path.basename(fpath),
			'type'      : 'remote_error',
			'category'  : getattr(exception, 'category', 'remote_error'),
			'exception' : exception.args[0] if exception.args else text_type(exception)
		}

		print(json.dumps(data))

class OutputHandler_yara(OutputHandler):
	def __init__(self):
		self.rule_enc = ''.join(chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else '_' for c in range(256))

	def print_match(self, fpath, page, name, match):
		if name in self.cnt:
			self.cnt[name] += 1
		else:
			self.cnt[name] = 1
		
		string_id = "$%s%d" % (name, self.cnt[name])
		self.sids.append(string_id)
		string_value = match.replace('\\', '\\\\')
		print("\t\t%s = \"%s\"" % (string_id, string_value))

	def print_header(self, fpath):
		rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)

		print("rule %s" % (rule_name))
		print("{")
		print("\tstrings:")

		self.cnt = {}
		self.sids = []

	def print_footer(self, fpath):
		cond = ' or '.join(self.sids)

		print("\tcondition:")
		print("\t\t" + cond)
		print("}")
		
class OutputHandler_netflow(OutputHandler):
	def __init__(self):
		print("host 255.255.255.255")

	def print_match(self, fpath, page, name, match):
		data = {
			'type' : name,
			'match': match
		}
		if data["type"] == "IP":
			print(" or host %s " % data["match"])
