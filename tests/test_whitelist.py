import os

import pytest

from iocp import Parser
from iocp.Whitelist import (
	Whitelist,
	WhitelistError,
	load,
	migrate_legacy_dir,
	migrate_legacy_line,
	parse_line,
)


def make_whitelist(entries):
	wl = Whitelist()
	for ind_type, line in entries:
		kind, value = parse_line(line)
		wl.add(ind_type, kind, value)
	return wl


# --------------------------------------------------------------------------
# Match semantics matrix: exact / suffix / pattern x allow / lookalike deny
# --------------------------------------------------------------------------

@pytest.mark.parametrize('candidate,expected', [
	('example.com', True),
	('EXAMPLE.com', True),          # exact match is case-insensitive
	('www.example.com', False),     # exact does not cover subdomains
	('evil-example.com', False),    # lookalike prefix must not pass
	('example.com.evil.com', False),
	('example.com/path', False),
])
def test_exact_matrix(candidate, expected):
	wl = make_whitelist([('Host', 'exact:example.com')])
	assert wl.is_whitelisted('Host', candidate) is expected


@pytest.mark.parametrize('candidate,expected', [
	('www.example.com', True),
	('a.b.example.com', True),
	('WWW.EXAMPLE.COM', True),      # suffix match is case-insensitive
	('example.com', False),         # suffix requires the leading dot
	('evil-example.com', False),    # lookalike suffix must not pass
	('example.com.evil.com', False),
])
def test_suffix_matrix(candidate, expected):
	wl = make_whitelist([('Host', 'suffix:.example.com')])
	assert wl.is_whitelisted('Host', candidate) is expected


@pytest.mark.parametrize('candidate,expected', [
	('user@example.com', True),
	('user@EXAMPLE.com', True),
	('user@example.com.evil.tld', False),   # spoofed domain tail must not pass
	('user@notexample.com', False),
])
def test_suffix_email_matrix(candidate, expected):
	wl = make_whitelist([('Email', 'suffix:@example.com')])
	assert wl.is_whitelisted('Email', candidate) is expected


@pytest.mark.parametrize('candidate,expected', [
	('http://example.com/report', True),
	('https://www.example.com/', True),
	('http://evil-example.com/', False),        # lookalike host must not pass
	('http://example.com.evil.tld/', False),    # official domain as prefix must not pass
	('http://example.com@evil.tld/', False),    # userinfo disguise must not pass
])
def test_pattern_matrix(candidate, expected):
	wl = make_whitelist([('URL', 'pattern:^https?://(www\\.)?example\\.com/')])
	assert wl.is_whitelisted('URL', candidate) is expected


def test_pattern_is_explicit_search_semantics():
	# A pattern entry keeps regex search semantics by explicit choice.
	wl = make_whitelist([('IP', 'pattern:^192\\.168\\.')])
	assert wl.is_whitelisted('IP', '192.168.1.1') is True
	assert wl.is_whitelisted('IP', '10.0.0.1') is False


# --------------------------------------------------------------------------
# IOC type binding
# --------------------------------------------------------------------------

def test_entries_are_bound_to_their_ioc_type():
	wl = make_whitelist([
		('Host', 'exact:example.com'),
		('Email', 'suffix:@example.com'),
	])
	assert wl.is_whitelisted('Host', 'example.com') is True
	assert wl.is_whitelisted('URL', 'http://example.com/') is False
	assert wl.is_whitelisted('Email', 'example.com') is False
	assert wl.is_whitelisted('IP', 'example.com') is False


def test_unknown_type_fails_closed():
	wl = make_whitelist([('Host', 'exact:example.com')])
	assert wl.is_whitelisted('Filename', 'example.com') is False


# --------------------------------------------------------------------------
# Fail closed: conflicts and bad expressions abort the load
# --------------------------------------------------------------------------

@pytest.mark.parametrize('line', [
	'pattern:([unclosed',       # invalid regex
	'regex:example.com',        # unknown kind
	'example\\.com$',           # legacy bare line without kind prefix
	'exact:',                   # empty value
	':example.com',             # empty kind
])
def test_bad_expressions_fail_closed(line):
	with pytest.raises(WhitelistError):
		make_whitelist([('Host', line)])


def test_duplicate_entries_fail_closed():
	with pytest.raises(WhitelistError):
		make_whitelist([
			('Host', 'exact:example.com'),
			('Host', 'exact:example.com'),
		])


def test_conflicting_kinds_fail_closed():
	with pytest.raises(WhitelistError):
		make_whitelist([
			('Host', 'exact:example.com'),
			('Host', 'suffix:example.com'),
		])


def test_unknown_ioc_type_fails_closed(tmp_path):
	wl_dir = tmp_path / 'whitelists'
	wl_dir.mkdir()
	(wl_dir / 'whitelist_Bogus.ini').write_text('exact:example.com\n')
	with pytest.raises(WhitelistError):
		load(str(wl_dir), valid_types=['Host'])


def test_load_dir_scoped_format(tmp_path):
	wl_dir = tmp_path / 'whitelists'
	wl_dir.mkdir()
	(wl_dir / 'whitelist_Host.ini').write_text(
		'# comment\n\nexact:example.com\nsuffix:.example.org\n')
	wl = load(str(wl_dir), valid_types=['Host'])
	assert wl.is_whitelisted('Host', 'example.com') is True
	assert wl.is_whitelisted('Host', 'www.example.org') is True
	assert wl.is_whitelisted('Host', 'evil-example.com') is False


# --------------------------------------------------------------------------
# Legacy migration
# --------------------------------------------------------------------------

@pytest.mark.parametrize('legacy,expected', [
	('acm\\.org$', ['exact:acm.org', 'suffix:.acm.org']),
	('@fireeye.com', ['suffix:@fireeye.com']),
	('^192\\.168\\.', ['pattern:^192\\.168\\.']),
	('^http:\\/\\/blog.example.com\\/', ['pattern:^http:\\/\\/blog.example.com\\/']),
])
def test_migrate_legacy_line(legacy, expected):
	assert migrate_legacy_line(legacy) == expected


def test_migrated_legacy_dir_loads_and_denies_lookalikes(tmp_path):
	legacy_dir = tmp_path / 'legacy'
	legacy_dir.mkdir()
	(legacy_dir / 'whitelist_Host.ini').write_text('example\\.com$\n')
	(legacy_dir / 'whitelist_Email.ini').write_text('@example.com\n')

	out_dir = tmp_path / 'scoped'
	migrated = migrate_legacy_dir(str(legacy_dir), str(out_dir))
	assert len(migrated) == 2

	wl = load(str(out_dir), valid_types=['Host', 'Email'])
	assert wl.is_whitelisted('Host', 'example.com') is True
	assert wl.is_whitelisted('Host', 'www.example.com') is True
	assert wl.is_whitelisted('Host', 'evil-example.com') is False
	assert wl.is_whitelisted('Email', 'user@example.com') is True
	assert wl.is_whitelisted('Email', 'user@example.com.evil.tld') is False


# --------------------------------------------------------------------------
# Parser integration against the shipped scoped whitelists
# --------------------------------------------------------------------------

class RecordingHandler(object):
	def __init__(self):
		self.matches = []

	def print_match(self, fpath, page, name, match):
		self.matches.append((name, match))

	def print_header(self, fpath):
		pass

	def print_footer(self, fpath):
		pass

	def print_error(self, fpath, exception):
		raise exception


@pytest.fixture(scope='module')
def parser():
	return Parser.Parser(input_format='txt', output_handler=RecordingHandler())


@pytest.mark.parametrize('candidate,expected', [
	('cisco.com', True),
	('www.cisco.com', True),
	('evil-cisco.com', False),          # the reported bypass is closed
	('cisco.com.evil.tld', False),
	('notcisco.com', False),
])
def test_shipped_host_whitelist(parser, candidate, expected):
	assert parser.is_whitelisted(candidate, 'Host') is expected


def test_parser_pipeline_drops_whitelisted_and_reports_evil(parser):
	parser.handler.matches = []
	parser.parse_page('report.txt', 'c2 at evil-cisco.com mirrors www.cisco.com', 1)
	host_matches = [m for t, m in parser.handler.matches if t == 'Host']
	assert 'evil-cisco.com' in host_matches
	assert 'www.cisco.com' not in host_matches
