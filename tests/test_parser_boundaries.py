import os

import pytest

from iocp.Parser import Parser


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


def read_fixture(name):
	with open(os.path.join(FIXTURE_DIR, name), encoding='utf-8') as handle:
		return handle.read()


def index(records):
	return {(record['type'], record['match']) for record in records}


@pytest.fixture
def parser():
	return Parser(input_format='txt', dedup=True)


@pytest.fixture
def raw_parser():
	return Parser(input_format='txt', dedup=False)


def test_url_trailing_punctuation_is_trimmed(parser):
	records = parser.extract_text(
		"See http://evil.example.com/path/payload. Next sentence."
	)
	assert index(records) == {('URL', 'http://evil.example.com/path/payload')}


def test_parenthesised_url_keeps_content_only(parser):
	records = parser.extract_text("Visit (https://cdn.example.org/a/b) now.")
	assert index(records) == {('URL', 'https://cdn.example.org/a/b')}


def test_adjacent_urls_are_split(parser):
	records = parser.extract_text(
		"URLs http://a.example.com/x,http://b.example.com/y both C2"
	)
	urls = [r['match'] for r in records if r['type'] == 'URL']
	assert urls == ['http://a.example.com/x', 'http://b.example.com/y']


def test_query_and_fragment_url_is_preserved(parser):
	records = parser.extract_text(
		"query http://cdn.example.net/search?q=a&b=c#frag!"
	)
	assert ('URL', 'http://cdn.example.net/search?q=a&b=c#frag') in index(records)


def test_host_trailing_brackets_and_dots_are_trimmed(parser):
	records = parser.extract_text("host bad.example.com); next")
	assert index(records) == {('Host', 'bad.example.com')}


def test_defanged_indicators_are_refanged(parser):
	records = parser.extract_text(
		"bad[.]example[.]com and http://evil[.]example[.]com/c2"
	)
	assert ('Host', 'bad.example.com') in index(records)
	assert ('URL', 'http://evil.example.com/c2') in index(records)


def test_filepath_overrides_embedded_filename(parser):
	records = parser.extract_text(
		"Dropped to C:\\Users\\victim\\Downloads\\invoice.exe and ran"
	)
	assert index(records) == {
		('Filepath', 'C:\\Users\\victim\\Downloads\\invoice.exe'),
	}


def test_standalone_filename_still_detected(parser):
	records = parser.extract_text("standalone payload.exe dropped")
	assert index(records) == {('Filename', 'payload.exe')}


def test_url_overrides_embedded_host_and_ip(parser):
	records = parser.extract_text("URL http://203.0.113.7/admin.php here")
	assert index(records) == {('URL', 'http://203.0.113.7/admin.php')}


def test_standalone_ip_not_swallowed(parser):
	records = parser.extract_text("IPs 203.0.113.7 and 198.51.100.9 listed")
	assert {r['match'] for r in records if r['type'] == 'IP'} == {
		'203.0.113.7',
		'198.51.100.9',
	}


def test_email_keeps_full_domain(parser):
	records = parser.extract_text("mail attacker@evil.example.co.uk ok")
	assert index(records) == {('Email', 'attacker@evil.example.co.uk')}


def test_normalized_dedup_collapses_variants(parser):
	records = parser.extract_text(
		"EVIL.Example.COM and evil.example.com plus bad[.]example[.]com "
		"and bad.example.com"
	)
	hosts = sorted(r['match'] for r in records if r['type'] == 'Host')
	assert hosts == ['EVIL.Example.COM', 'bad.example.com']


def test_dedup_disabled_keeps_repeated_indicators(raw_parser):
	records = raw_parser.extract_text(
		"d41d8cd98f00b204e9800998ecf8427e d41d8cd98f00b204e9800998ecf8427e"
	)
	assert len(records) == 2
	assert all(r['type'] == 'MD5' for r in records)


def test_whitelisted_indicators_are_skipped(parser):
	records = parser.extract_text(
		"whitelisted 192.168.10.20 and www.google.com, real 8.8.4.4"
	)
	assert index(records) == {('IP', '8.8.4.4')}


def test_record_offsets_point_at_raw_evidence(parser):
	text = "see http://evil[.]example[.]com/c2 now"
	records = parser.extract_text(text)
	url = next(r for r in records if r['type'] == 'URL')
	assert text[url['start']:url['end']] == url['raw']
	assert url['raw'] == 'http://evil[.]example[.]com/c2'
	assert url['match'] == 'http://evil.example.com/c2'


def test_boundary_fixture_matches_expected_indicators(parser):
	text = read_fixture('boundary_report.txt')
	records = parser.extract_text(text)

	expected = {
		('URL', 'http://evil.example.com/path/payload'),
		('URL', 'https://cdn.example.org/a/b'),
		('URL', 'http://a.example.com/x'),
		('URL', 'http://b.example.com/y'),
		('URL', 'http://evil.example.com/c2'),
		('URL', 'http://203.0.113.7/admin.php'),
		('URL', 'http://cdn.example.net/search?q=a&b=c#frag'),
		('Host', 'bad.example.net'),
		('Host', 'bad.example.com'),
		('Host', 'one.example.com'),
		('Host', 'two.example.org'),
		('Host', 'EVIL.Example.COM'),
		('IP', '198.51.100.9'),
		('Email', 'attacker@evil.example.co.uk'),
		('MD5', 'd41d8cd98f00b204e9800998ecf8427e'),
		('Filepath', 'C:\\Users\\victim\\Downloads\\invoice.exe'),
	}
	assert index(records) == expected

	for record in records:
		assert text[record['start']:record['end']] == record['raw']


def test_plain_report_produces_no_indicators(parser):
	text = read_fixture('plain_report.txt')
	assert parser.extract_text(text) == []
