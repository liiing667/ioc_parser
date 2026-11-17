import pytest

from iocp import Parser


PUBLIC_IP = '1.1.1.1'
PRIVATE_IPS = ('127.0.0.1', '10.10.20.30', '192.168.1.10', '169.254.169.254', '::1')


class RecordingHandler(object):
	def __init__(self):
		self.matches = []
		self.errors = []
		self.remote_errors = []

	def print_match(self, fpath, page, name, match):
		self.matches.append((fpath, page, name, match))

	def print_header(self, fpath):
		pass

	def print_footer(self, fpath):
		pass

	def print_error(self, fpath, exception):
		self.errors.append((fpath, exception))

	def print_remote_error(self, fpath, exception):
		self.remote_errors.append((fpath, exception))


@pytest.fixture
def recording_handler():
	return RecordingHandler()


@pytest.fixture
def make_parser(recording_handler):
	def _make(input_format='txt', **fetcher_overrides):
		parser = Parser.Parser(
			input_format=input_format,
			output_handler=recording_handler)
		original_factory = parser.make_remote_fetcher

		def factory():
			fetcher = original_factory()
			for name, value in fetcher_overrides.items():
				setattr(fetcher, name, value)
			return fetcher

		parser.make_remote_fetcher = factory
		return parser

	return _make


@pytest.fixture
def public_resolver(monkeypatch):
	from iocp import Remote

	def _resolve(host, port):
		return [PUBLIC_IP]

	monkeypatch.setattr(Remote, '_default_resolve', staticmethod(_resolve))
	return _resolve


@pytest.fixture
def private_resolver(monkeypatch):
	from iocp import Remote

	def _resolve(host, port):
		return ['127.0.0.1']

	monkeypatch.setattr(Remote, '_default_resolve', staticmethod(_resolve))
	return _resolve


@pytest.fixture
def failing_resolver(monkeypatch):
	import socket
	from iocp import Remote

	def _resolve(host, port):
		raise socket.gaierror(8, 'hostname resolution failed')

	monkeypatch.setattr(Remote, '_default_resolve', staticmethod(_resolve))
	return _resolve
