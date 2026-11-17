#!/usr/bin/env python

###################################################################################################
#
# Copyright (c) 2015, Armin Buescher (armin.buescher@googlemail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
###################################################################################################
#
# File:             iocp.py
# Description:      IOC Parser is a tool to extract indicators of compromise from security reports
#                   in PDF format.
# Usage:            iocp.py [-h] [-p INI] [-f FORMAT] PDF
# Author:           Armin Buescher (@armbues)
# Contributors:     Angelo Dell'Aera (@angelodellaera)
# Thanks to:        Jose Ramon Palanco
#                   Koen Van Impe (@cudeso)
#
###################################################################################################

import os
import sys
import fnmatch
import glob
import re
try:
	import configparser as ConfigParser
except ImportError:
	import ConfigParser
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

# Import optional third-party libraries
IMPORTS = []
try:
	from PyPDF2 import PdfFileReader
	IMPORTS.append('pypdf2')
except ImportError:
	pass
try:
	from pdfminer.pdfpage import PDFPage
	from pdfminer.pdfinterp import PDFResourceManager
	from pdfminer.converter import TextConverter
	from pdfminer.pdfinterp import PDFPageInterpreter
	from pdfminer.layout import LAParams
	IMPORTS.append('pdfminer')
except ImportError:
	pass
try:
	from bs4 import BeautifulSoup
	IMPORTS.append('beautifulsoup')
except ImportError:
	pass
try:
	import requests
	IMPORTS.append('requests')
except ImportError:
	pass

# Import project source files
import iocp
from iocp import Output

# Output types that embed other indicators are resolved first when candidate
# spans overlap (e.g. a Filepath contains a Filename, a URL contains a Host).
TYPE_PRIORITY = {
	'Filepath': 90,
	'URL': 80,
	'Registry': 70,
	'Email': 60,
	'Filename': 50,
	'SHA256': 40,
	'SHA1': 30,
	'MD5': 20,
	'Host': 15,
	'IP': 10,
	'CVE': 10,
}

# Characters that legitimately end prose but never end an indicator itself.
TRAILING_PUNCTUATION = '.,;:!?"\'’”…'


class CollectingHandler(Output.OutputHandler):
	"""Output handler that keeps parsed records instead of printing them."""

	def __init__(self):
		self.records = []

	def print_match(self, fpath, page, name, match, record=None):
		self.records.append({
			'path': fpath,
			'page': page,
			'type': name,
			'match': match,
			'raw': record['raw'],
			'start': record['start'],
			'end': record['end'],
		})


class Parser(object):
	patterns = {}
	defang = {}

	def __init__(self, patterns_ini=None, input_format='pdf', dedup=False, library='pdfminer', output_format='csv', output_handler=None):
		basedir = iocp.get_basedir()

		if patterns_ini is None:
			patterns_ini = os.path.join(basedir, 'data/patterns.ini')
		self.load_patterns(patterns_ini)

		wldir = os.path.join(basedir, 'data/whitelists')
		self.whitelist = self.load_whitelists(wldir)

		self.dedup = dedup
		if output_handler:
			self.handler = output_handler
		else:
			self.handler = Output.getHandler(output_format)

		self.ext_filter = "*." + input_format
		parser_format = "parse_" + input_format
		try:
			self.parser_func = getattr(self, parser_format)
		except AttributeError:
			e = 'Selected parser format is not supported: %s' % (input_format)
			raise NotImplementedError(e)

		self.library = library
		self.dedup_store = set()
		if input_format == 'pdf':
			if library not in IMPORTS:
				e = 'Selected PDF parser library not found: %s' % (library)
				raise ImportError(e)
		elif input_format == 'html':
			if 'beautifulsoup' not in IMPORTS:
				e = 'HTML parser library not found: BeautifulSoup'
				raise ImportError(e)

	def load_patterns(self, fpath):
		config = ConfigParser.ConfigParser()
		with open(fpath) as f:
			if hasattr(config, 'read_file'):
				config.read_file(f)
			else:
				config.readfp(f)

		for ind_type in config.sections():
			try:
				ind_pattern = config.get(ind_type, 'pattern')
			except:
				continue

			if ind_pattern:
				flags = re.IGNORECASE if config.has_option(ind_type, 'case_insensitive') else 0
				ind_regex = re.compile(ind_pattern, flags)
				self.patterns[ind_type] = ind_regex

			try:
				ind_defang = config.get(ind_type, 'defang')
			except:
				continue

			if ind_defang:
				self.defang[ind_type] = True

	def load_whitelists(self, fpath):
		whitelist = {}

		searchdir = os.path.join(fpath, "whitelist_*.ini")
		fpaths = glob.glob(searchdir)
		for fpath in fpaths:
			t = os.path.splitext(os.path.split(fpath)[1])[0].split('_',1)[1]
			patterns = [line.strip() for line in open(fpath)]
			whitelist[t]  = [re.compile(p) for p in patterns]

		return whitelist

	def is_whitelisted(self, ind_match, ind_type):
		try:
			for w in self.whitelist[ind_type]:
				if w.search(ind_match):
					return True
		except KeyError as e:
			pass
		return False

	def _trim_span(self, data, start, end):
		"""Strip sentence punctuation and unmatched trailing brackets from a span."""
		while end > start:
			ch = data[end - 1]
			if ch in TRAILING_PUNCTUATION:
				end -= 1
				continue
			if ch in ')]}':
				open_ch = {')': '(', ']': '[', '}': '{'}[ch]
				if data.count(open_ch, start, end) <= data.count(ch, start, end):
					end -= 1
					continue
			break
		return start, end

	def _defang_value(self, ind_type, value):
		if ind_type in self.defang:
			return re.sub(r'\[\.\]', '.', value)
		return value

	def _normalize(self, ind_type, value):
		"""Build a canonical key so surface variants of one IOC dedup together."""
		value = self._defang_value(ind_type, value).strip().lower()
		if ind_type == 'URL':
			match = re.match(r'^([a-z]{3,})://([^/]*)(/.*)?$', value)
			if match:
				scheme, host, path = match.group(1), match.group(2), match.group(3) or ''
				host = host.rstrip('.;:,!?')
				path = path.rstrip('.;:,!?)\\]}\'\"')
				value = '%s://%s%s' % (scheme, host, path)
		return value

	def _collect_candidates(self, data):
		candidates = []
		for ind_type, ind_regex in self.patterns.items():
			for match in ind_regex.finditer(data):
				start, end = match.span(1) if match.groups() else match.span()
				start, end = self._trim_span(data, start, end)
				if end <= start:
					continue

				raw = data[start:end]
				value = self._defang_value(ind_type, raw)
				if self.is_whitelisted(value, ind_type):
					continue

				candidates.append({
					'type': ind_type,
					'raw': raw,
					'value': value,
					'start': start,
					'end': end,
				})
		return candidates

	def _resolve_overlaps(self, candidates):
		"""Drop lower-priority indicators fully contained in a stronger one."""
		ordered = sorted(
			candidates,
			key=lambda c: (c['start'], -TYPE_PRIORITY.get(c['type'], 0), -(c['end'] - c['start']))
		)
		accepted = []
		for cand in ordered:
			covered = False
			for kept in accepted:
				if cand['start'] >= kept['start'] and cand['end'] <= kept['end']:
					covered = True
					break
			if not covered:
				accepted.append(cand)
		accepted.sort(key=lambda c: (c['start'], c['end']))
		return accepted

	def extract_text(self, data, fpath='<string>', page_num=1):
		"""Parse plain text and return structured records with evidence offsets."""
		candidates = self._collect_candidates(data)
		records = self._resolve_overlaps(candidates)

		dedup_store = set()
		results = []
		for record in records:
			if self.dedup:
				key = (record['type'], self._normalize(record['type'], record['value']))
				if key in dedup_store:
					continue
				dedup_store.add(key)
			results.append({
				'path': fpath,
				'page': page_num,
				'type': record['type'],
				'match': record['value'],
				'raw': record['raw'],
				'start': record['start'],
				'end': record['end'],
			})
		return results

	def parse_page(self, fpath, data, page_num):
		candidates = self._collect_candidates(data)
		records = self._resolve_overlaps(candidates)

		for record in records:
			if self.dedup:
				key = (record['type'], self._normalize(record['type'], record['value']))
				if key in self.dedup_store:
					continue
				self.dedup_store.add(key)

			self.handler.print_match(
				fpath, page_num, record['type'], record['value'], record=record
			)

	def parse_pdf_pypdf2(self, f, fpath):
		try:
			pdf = PdfFileReader(f, strict = False)

			self.dedup_store = set()

			self.handler.print_header(fpath)
			page_num = 0
			for page in pdf.pages:
				page_num += 1

				data = page.extractText()

				self.parse_page(fpath, data, page_num)
			self.handler.print_footer(fpath)
		except (KeyboardInterrupt, SystemExit):
			raise

	def parse_pdf_pdfminer(self, f, fpath):
		try:
			laparams = LAParams()
			laparams.all_texts = True  
			rsrcmgr = PDFResourceManager()
			pagenos = set()

			self.dedup_store = set()

			self.handler.print_header(fpath)
			page_num = 0
			for page in PDFPage.get_pages(f, pagenos, check_extractable=True):
				page_num += 1

				retstr = StringIO()
				device = TextConverter(rsrcmgr, retstr, codec='utf-8', laparams=laparams)
				interpreter = PDFPageInterpreter(rsrcmgr, device)
				interpreter.process_page(page)
				data = retstr.getvalue()
				retstr.close()

				self.parse_page(fpath, data, page_num)
			self.handler.print_footer(fpath)
		except (KeyboardInterrupt, SystemExit):
			raise

	def parse_pdf(self, f, fpath):
		parser_format = "parse_pdf_" + self.library
		try:
			self.parser_func = getattr(self, parser_format)
		except AttributeError:
			e = 'Selected PDF parser library is not supported: %s' % (self.library)
			raise NotImplementedError(e)
			
		self.parser_func(f, fpath)

	def parse_txt(self, f, fpath):
		try:
			self.dedup_store = set()

			data = f.read()
			if isinstance(data, bytes):
				data = data.decode('utf-8', 'replace')
			self.handler.print_header(fpath)
			self.parse_page(fpath, data, 1)
			self.handler.print_footer(fpath)
		except (KeyboardInterrupt, SystemExit):
			raise

	def parse_html(self, f, fpath):
		try:
			self.dedup_store = set()

			data = f.read()
			if isinstance(data, bytes):
				data = data.decode('utf-8', 'replace')
			soup = BeautifulSoup(data)
			html = soup.findAll(text=True)

			text = u''
			for elem in html:
				if elem.parent.name in ['style', 'script', '[document]', 'head', 'title']:
					continue
				elif re.match('<!--.*-->', str(elem)):
					continue
				else:
					text += str(elem)

			self.handler.print_header(fpath)
			self.parse_page(fpath, text, 1)
			self.handler.print_footer(fpath)
		except (KeyboardInterrupt, SystemExit):
			raise

	def parse(self, path):
		try:
			if path.startswith('http://') or path.startswith('https://'):
				if 'requests' not in IMPORTS:
					e = 'HTTP library not found: requests'
					raise ImportError(e)
				headers = { 'User-Agent': 'Mozilla/5.0 Gecko Firefox' }
				r = requests.get(path, headers=headers)
				r.raise_for_status()
				f = StringIO(r.content)
				self.parser_func(f, path)
				return
			elif os.path.isfile(path):
				with open(path, 'rb') as f:
					self.parser_func(f, path)
				return
			elif os.path.isdir(path):
				for walk_root, walk_dirs, walk_files in os.walk(path):
					for walk_file in fnmatch.filter(walk_files, self.ext_filter):
						fpath = os.path.join(walk_root, walk_file)
						with open(fpath, 'rb') as f:
							self.parser_func(f, fpath)
				return

			e = 'File path is not a file, directory or URL: %s' % (path)
			raise IOError(e)
		except (KeyboardInterrupt, SystemExit):
			raise
		except Exception as e:
			self.handler.print_error(path, e)
