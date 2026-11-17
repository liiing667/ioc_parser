import contextlib
import socket

import pytest
import responses

from iocp import Remote


BASE_URL = 'http://report.example.test/report.txt'


def make_fetcher(resolver, **overrides):
	kwargs = {'input_format': 'txt', 'resolver': resolver}
	kwargs.update(overrides)
	return Remote.RemoteFetcher(**kwargs)


def public_resolver(host, port):
	return ['1.1.1.1']


def private_resolver(host, port):
	return ['127.0.0.1']


@responses.activate
def test_fetch_returns_body_within_limits():
	responses.add(responses.GET, BASE_URL, body=b'192.0.2.10 appears here',
	              status=200, content_type='text/plain')
	fetcher = make_fetcher(public_resolver)

	content, final_url = fetcher.fetch(BASE_URL)

	assert content == b'192.0.2.10 appears here'
	assert final_url == BASE_URL
	request = responses.calls[0].request
	assert request.headers['User-Agent'] == Remote.DEFAULT_USER_AGENT


@pytest.mark.parametrize('ip', ['127.0.0.1', '10.10.20.30', '192.168.1.10',
                                '169.254.169.254', '0.0.0.0', '::1'])
def test_private_ip_literal_is_blocked(ip):
	scheme = 'https' if ':' in ip else 'http'
	url = '%s://[%s]/report' % (scheme, ip) if ':' in ip else 'http://%s/report' % ip
	fetcher = make_fetcher(public_resolver)

	with pytest.raises(Remote.PrivateTargetError) as exc_info:
		fetcher.fetch(url)
	assert exc_info.value.category == 'private_target'
	assert len(responses.calls) == 0


@pytest.mark.parametrize('encoded', ['2130706433', '0x7f000001', '017700000001'])
def test_encoded_loopback_notation_is_blocked(encoded):
	fetcher = make_fetcher(public_resolver)

	with pytest.raises(Remote.PrivateTargetError):
		fetcher.ensure_public_target('http://%s/admin' % encoded)
	assert len(responses.calls) == 0


@responses.activate
def test_private_dns_resolution_is_blocked():
	responses.add(responses.GET, BASE_URL, body=b'x', status=200,
	              content_type='text/plain')
	fetcher = make_fetcher(private_resolver)

	with pytest.raises(Remote.PrivateTargetError):
		fetcher.fetch(BASE_URL)
	assert len(responses.calls) == 0


def test_non_http_scheme_is_blocked():
	fetcher = make_fetcher(public_resolver)

	with pytest.raises(Remote.PrivateTargetError):
		fetcher.fetch('file:///etc/passwd')
	with pytest.raises(Remote.PrivateTargetError):
		fetcher.fetch('gopher://report.example.test/looted')


@responses.activate
def test_redirect_to_private_target_is_blocked():
	responses.add(responses.GET, BASE_URL, status=302,
	              adding_headers={'Location': 'http://169.254.169.254/latest/meta-data'})
	fetcher = make_fetcher(public_resolver)

	with pytest.raises(Remote.PrivateTargetError):
		fetcher.fetch(BASE_URL)
	assert len(responses.calls) == 1


@responses.activate
def test_redirect_chain_is_followed_and_revalidated():
	mid_url = 'http://cdn.example.test/moved.txt'
	responses.add(responses.GET, BASE_URL, status=301,
	              adding_headers={'Location': mid_url})
	responses.add(responses.GET, mid_url, body=b'198.51.100.99', status=200,
	              content_type='text/plain')
	fetcher = make_fetcher(public_resolver)

	content, final_url = fetcher.fetch(BASE_URL)
	assert content == b'198.51.100.99'
	assert final_url == mid_url
	assert len(responses.calls) == 2


@responses.activate
def test_redirect_limit_is_enforced():
	responses.add(responses.GET, BASE_URL, status=302,
	              adding_headers={'Location': BASE_URL})
	fetcher = make_fetcher(public_resolver, max_redirects=2)

	with pytest.raises(Remote.ResponseLimitError) as exc_info:
		fetcher.fetch(BASE_URL)
	assert exc_info.value.category == 'response_limit'
	assert 'redirect' in str(exc_info.value)
	assert len(responses.calls) == 3


@responses.activate
def test_declared_content_length_over_limit_is_aborted():
	responses.add(responses.GET, BASE_URL, body=b'x' * 4096, status=200,
	              content_type='text/plain',
	              adding_headers={'Content-Length': '4096'})
	fetcher = make_fetcher(public_resolver, max_bytes=1024)

	with pytest.raises(Remote.ResponseLimitError) as exc_info:
		fetcher.fetch(BASE_URL)
	assert '4096' in str(exc_info.value)
	assert len(responses.calls) == 1


@responses.activate
def test_streamed_body_over_limit_is_aborted():
	responses.add(responses.GET, BASE_URL, body=b'x' * 2048, status=200,
	              content_type='text/plain')
	fetcher = make_fetcher(public_resolver, max_bytes=1024, chunk_size=256)

	with pytest.raises(Remote.ResponseLimitError):
		fetcher.fetch(BASE_URL)


@responses.activate
def test_disallowed_content_type_is_rejected():
	responses.add(responses.GET, BASE_URL, body=b'<html/>', status=200,
	              content_type='application/zip')
	fetcher = make_fetcher(public_resolver)

	with pytest.raises(Remote.ResponseLimitError):
		fetcher.fetch(BASE_URL)


@responses.activate
def test_missing_content_type_is_rejected():
	responses.add(responses.GET, BASE_URL, body=b'data', status=200,
	              content_type='')
	fetcher = make_fetcher(public_resolver)

	with pytest.raises(Remote.ResponseLimitError):
		fetcher.fetch(BASE_URL)


@responses.activate
def test_http_error_status_is_fetch_error():
	responses.add(responses.GET, BASE_URL, status=500)
	fetcher = make_fetcher(public_resolver)

	with pytest.raises(Remote.RemoteFetchError) as exc_info:
		fetcher.fetch(BASE_URL)
	assert exc_info.value.category == 'fetch_error'
	assert '500' in str(exc_info.value)


@responses.activate
def test_timeout_is_classified_as_limit_error():
	import requests

	def raise_timeout(request):
		raise requests.ConnectTimeout('connect timed out')

	responses.add_callback(responses.GET, BASE_URL, callback=raise_timeout)
	fetcher = make_fetcher(public_resolver, timeout=1)

	with pytest.raises(Remote.ResponseLimitError) as exc_info:
		fetcher.fetch(BASE_URL)
	assert 'Timed out' in str(exc_info.value)


@responses.activate
def test_connection_error_is_fetch_error():
	import requests

	def raise_connection_error(request):
		raise requests.ConnectionError('connection refused')

	responses.add_callback(responses.GET, BASE_URL, callback=raise_connection_error)
	fetcher = make_fetcher(public_resolver)

	with pytest.raises(Remote.RemoteFetchError):
		fetcher.fetch(BASE_URL)


def test_dns_failure_is_fetch_error():
	def failing_resolve(host, port):
		raise socket.gaierror(-2, 'Name or service not known')

	fetcher = make_fetcher(failing_resolve)

	with pytest.raises(Remote.RemoteFetchError) as exc_info:
		fetcher.fetch(BASE_URL)
	assert 'DNS' in str(exc_info.value)


def test_empty_dns_result_is_fetch_error():
	fetcher = make_fetcher(lambda host, port: [])

	with pytest.raises(Remote.RemoteFetchError) as exc_info:
		fetcher.fetch(BASE_URL)
	assert 'no address' in str(exc_info.value)


def test_non_ip_resolution_result_is_fetch_error():
	fetcher = make_fetcher(lambda host, port: ['not-an-ip-literal'])

	with pytest.raises(Remote.RemoteFetchError) as exc_info:
		fetcher.fetch(BASE_URL)
	assert 'not an IP literal' in str(exc_info.value)


@responses.activate
def test_malformed_content_length_is_ignored_then_streamed_limit_applies():
	responses.add(responses.GET, BASE_URL, body=b'x' * 2048, status=200,
	              content_type='text/plain',
	              adding_headers={'Content-Length': 'not-a-number'})
	fetcher = make_fetcher(public_resolver, max_bytes=1024, chunk_size=256)

	with pytest.raises(Remote.ResponseLimitError):
		fetcher.fetch(BASE_URL)


@contextlib.contextmanager
def _fake_open_remote(stream, url):
	yield stream, url


def test_keyboard_interrupt_is_not_wrapped_as_parse_error(monkeypatch):
	from io import BytesIO

	fetcher = make_fetcher(public_resolver)
	monkeypatch.setattr(fetcher, 'open_remote',
	                    lambda url: _fake_open_remote(BytesIO(b'data'), url))

	def interrupt_parser(stream, fpath):
		raise KeyboardInterrupt()

	with pytest.raises(KeyboardInterrupt):
		fetcher.read_transaction(BASE_URL, interrupt_parser)


def test_remote_read_error_from_parser_is_not_re_wrapped(monkeypatch):
	from io import BytesIO

	fetcher = make_fetcher(public_resolver)
	monkeypatch.setattr(fetcher, 'open_remote',
	                    lambda url: _fake_open_remote(BytesIO(b'data'), url))

	def raise_remote_error(stream, fpath):
		raise Remote.ResponseLimitError('from inside the parser')

	with pytest.raises(Remote.ResponseLimitError):
		fetcher.read_transaction(BASE_URL, raise_remote_error)


def test_unknown_input_format_requires_explicit_content_types():
	with pytest.raises(ValueError):
		Remote.RemoteFetcher(input_format='rtf', resolver=public_resolver)

	fetcher = Remote.RemoteFetcher(
		input_format='rtf', resolver=public_resolver,
		allowed_content_types=('application/rtf',))
	assert fetcher.allowed_content_types == ('application/rtf',)


@responses.activate
def test_read_transaction_wraps_parser_failures():
	responses.add(responses.GET, BASE_URL, body=b'payload', status=200,
	              content_type='text/plain')
	fetcher = make_fetcher(public_resolver)

	def broken_parser(stream, fpath):
		raise ValueError('decoder exploded')

	with pytest.raises(Remote.RemoteParseError) as exc_info:
		fetcher.read_transaction(BASE_URL, broken_parser)
	assert exc_info.value.category == 'parse_error'
	assert 'decoder exploded' in str(exc_info.value)


def test_missing_requests_library_is_fetch_error(monkeypatch):
	fetcher = Remote.RemoteFetcher(input_format='txt', resolver=public_resolver)
	monkeypatch.setattr(Remote, 'requests', None)
	with pytest.raises(Remote.RemoteFetchError):
		fetcher._get_session()
