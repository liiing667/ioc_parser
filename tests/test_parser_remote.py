import pytest
import responses

from iocp import Remote


TXT_URL = 'http://report.example.test/report.txt'
HTML_URL = 'http://report.example.test/report.html'


@responses.activate
def test_remote_txt_is_parsed_through_controlled_transaction(make_parser, public_resolver):
	responses.add(responses.GET, TXT_URL,
	              body=b'contact 198.51.100.23 in the report', status=200,
	              content_type='text/plain')
	parser = make_parser('txt')

	parser.parse(TXT_URL)

	assert len(parser.handler.matches) == 1
	fpath, page, ind_type, match = parser.handler.matches[0]
	assert fpath == TXT_URL
	assert ind_type == 'IP'
	assert match == '198.51.100.23'
	assert parser.handler.remote_errors == []


@responses.activate
def test_remote_html_uses_html_content_type_policy(make_parser, public_resolver):
	body = b'<html><body><p>host 198.51.100.24</p></body></html>'
	responses.add(responses.GET, HTML_URL, body=body, status=200,
	              content_type='text/html; charset=utf-8')
	parser = make_parser('html')

	parser.parse(HTML_URL)

	types = [match[2] for match in parser.handler.matches]
	assert 'IP' in types


@responses.activate
def test_pdf_content_type_policy_rejects_html_body(make_parser, public_resolver):
	url = 'http://report.example.test/report.pdf'
	responses.add(responses.GET, url, body=b'not really a pdf', status=200,
	              content_type='text/html')
	parser = make_parser('txt', allowed_content_types=Remote.CONTENT_TYPES['pdf'])

	with pytest.raises(Remote.ResponseLimitError) as exc_info:
		parser.parse(url)
	assert exc_info.value.category == 'response_limit'


@responses.activate
def test_pdf_content_type_policy_allows_pdf_body(make_parser, public_resolver):
	url = 'http://report.example.test/report.pdf'
	responses.add(responses.GET, url, body=b'%PDF-1.4 fake payload', status=200,
	              content_type='application/pdf')
	parser = make_parser('txt', allowed_content_types=Remote.CONTENT_TYPES['pdf'])

	parser.parse(url)

	assert parser.handler.remote_errors == []


@responses.activate
def test_private_target_is_reported_with_category_and_raised(make_parser, public_resolver):
	parser = make_parser('txt')

	with pytest.raises(Remote.PrivateTargetError):
		parser.parse('http://127.0.0.1/admin')

	assert len(parser.handler.remote_errors) == 1
	fpath, exception = parser.handler.remote_errors[0]
	assert fpath == 'http://127.0.0.1/admin'
	assert exception.category == 'private_target'
	assert parser.handler.errors == []


@responses.activate
def test_oversized_response_is_distinct_from_no_indicators(make_parser, public_resolver):
	responses.add(responses.GET, TXT_URL, body=b'x' * 8192, status=200,
	              content_type='text/plain')
	parser = make_parser('txt', max_bytes=1024, chunk_size=512)

	with pytest.raises(Remote.ResponseLimitError):
		parser.parse(TXT_URL)

	assert parser.handler.remote_errors
	assert parser.handler.errors == []


@responses.activate
def test_unparseable_remote_body_is_parse_error(make_parser, public_resolver):
	responses.add(responses.GET, TXT_URL, body=b'payload', status=200,
	              content_type='text/plain')
	parser = make_parser('txt')

	def explode(stream, fpath):
		raise ValueError('bad encoding')

	parser.parser_func = explode

	with pytest.raises(Remote.RemoteParseError) as exc_info:
		parser.parse(TXT_URL)
	assert exc_info.value.category == 'parse_error'
	_, exception = parser.handler.remote_errors[0]
	assert exception.category == 'parse_error'


@responses.activate
def test_remote_input_without_indicators_produces_no_errors(make_parser, public_resolver):
	responses.add(responses.GET, TXT_URL,
	              body=b'nothing of interest in this text', status=200,
	              content_type='text/plain')
	parser = make_parser('txt')

	parser.parse(TXT_URL)

	assert parser.handler.matches == []
	assert parser.handler.errors == []
	assert parser.handler.remote_errors == []


def test_local_txt_file_remains_unchanged(make_parser, tmp_path):
	report = tmp_path / 'report.txt'
	report.write_bytes(b'local host at 198.51.100.77 only')
	parser = make_parser('txt')

	parser.parse(str(report))

	assert len(parser.handler.matches) == 1
	assert parser.handler.matches[0][2] == 'IP'
	assert parser.handler.errors == []
	assert parser.handler.remote_errors == []


def test_local_html_file_remains_unchanged(make_parser, tmp_path):
	report = tmp_path / 'report.html'
	report.write_bytes(b'<html><body>see 198.51.100.78</body></html>')
	parser = make_parser('html')

	parser.parse(str(report))

	assert [match[2] for match in parser.handler.matches] == ['IP']
	assert parser.handler.errors == []


def test_local_missing_path_still_uses_generic_error(make_parser, tmp_path):
	parser = make_parser('txt')

	parser.parse(str(tmp_path / 'missing.txt'))

	assert len(parser.handler.errors) == 1
	assert parser.handler.remote_errors == []


def test_scheme_other_than_http_is_treated_as_remote_and_blocked(make_parser):
	parser = make_parser('txt')

	with pytest.raises(Remote.PrivateTargetError):
		parser.parse('ftp://report.example.test/report.txt')


@responses.activate
def test_direct_fetcher_usage_allows_custom_limits(make_parser, public_resolver):
	responses.add(responses.GET, TXT_URL, body=b'198.51.100.55', status=200,
	              content_type='text/plain')
	parser = make_parser('txt', timeout=3, max_redirects=1, max_bytes=2048)

	parser.parse(TXT_URL)

	fetcher = parser.make_remote_fetcher()
	assert fetcher.timeout == 3
	assert fetcher.max_redirects == 1
	assert fetcher.max_bytes == 2048
	assert parser.handler.matches[0][3] == '198.51.100.55'
