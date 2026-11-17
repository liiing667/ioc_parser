#!/usr/bin/env python

import contextlib
import ipaddress
import re
import socket
from io import BytesIO

try:
	import requests
except ImportError:
	requests = None


DEFAULT_TIMEOUT = 10
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_CHUNK_SIZE = 64 * 1024
DEFAULT_USER_AGENT = 'Mozilla/5.0 Gecko Firefox'

CONTENT_TYPES = {
	'pdf': ('application/pdf', 'application/x-pdf', 'application/octet-stream'),
	'html': ('text/html', 'application/xhtml+xml'),
	'txt': ('text/plain',),
}

REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class RemoteReadError(Exception):
	category = 'remote_error'


class PrivateTargetError(RemoteReadError):
	category = 'private_target'


class ResponseLimitError(RemoteReadError):
	category = 'response_limit'


class RemoteFetchError(RemoteReadError):
	category = 'fetch_error'


class RemoteParseError(RemoteReadError):
	category = 'parse_error'


def _default_resolve(host, port):
	infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
	return [info[4][0] for info in infos]


class RemoteFetcher(object):
	"""Fetches remote reports through a single constrained read transaction.

	Every request target (including each redirect hop) is validated to be a
	public HTTP(S) address.  Redirects, response size, content type and socket
	timeouts are bounded, and every failure is raised as a categorized
	RemoteReadError instead of being mixed into generic parser output.
	"""

	def __init__(self, input_format='pdf', timeout=DEFAULT_TIMEOUT,
			max_redirects=DEFAULT_MAX_REDIRECTS, max_bytes=DEFAULT_MAX_BYTES,
			chunk_size=DEFAULT_CHUNK_SIZE, allowed_content_types=None,
			user_agent=DEFAULT_USER_AGENT, session=None, resolver=None):
		if allowed_content_types is None:
			try:
				allowed_content_types = CONTENT_TYPES[input_format]
			except KeyError:
				raise ValueError('No content type policy for input format: %s' % (input_format))

		self.input_format = input_format
		self.timeout = timeout
		self.max_redirects = max_redirects
		self.max_bytes = max_bytes
		self.chunk_size = chunk_size
		self.allowed_content_types = tuple(t.lower() for t in allowed_content_types)
		self.user_agent = user_agent
		self.session = session
		self.resolve = resolver or _default_resolve

	def _get_session(self):
		if self.session is not None:
			return self.session
		if requests is None:
			raise RemoteFetchError('HTTP library not found: requests')
		return requests.Session()

	def ensure_public_target(self, url):
		from urllib.parse import urlsplit

		parsed = urlsplit(url)
		if parsed.scheme not in ('http', 'https'):
			raise PrivateTargetError('URL scheme is not allowed: %s' % (url))

		host = parsed.hostname
		if not host:
			raise PrivateTargetError('URL has no host component: %s' % (url))

		port = parsed.port or (443 if parsed.scheme == 'https' else 80)
		try:
			addresses = [ipaddress.ip_address(host)]
		except ValueError:
			normalized = self._normalize_numeric_host(host)
			if normalized is not None:
				addresses = [normalized]
			else:
				try:
					resolved = self.resolve(host, port)
				except socket.gaierror as e:
					raise RemoteFetchError('DNS resolution failed for host %s: %s' % (host, e))
				if not resolved:
					raise RemoteFetchError('DNS resolution returned no address for host %s' % (host))
				addresses = []
				for raw_ip in resolved:
					try:
						addresses.append(ipaddress.ip_address(raw_ip))
					except ValueError:
						raise RemoteFetchError('Resolved address is not an IP literal: %s' % (raw_ip))

		for ip in addresses:
			if not ip.is_global:
				raise PrivateTargetError('Target resolves to a non-public address %s: %s' % (ip, url))

	def _normalize_numeric_host(self, host):
		"""Decode alternate IPv4 encodings (decimal/octal/hex integers).

		Browsers accept forms such as http://2130706433/ for 127.0.0.1; treating
		them as ordinary DNS names would bypass the private address check.
		"""
		if ':' in host:
			return None
		if re.search(r'[a-z]', host, re.IGNORECASE) and not re.match(r'^0[xX][0-9a-fA-F]+$', host):
			return None
		try:
			packed = socket.inet_aton(host)
		except (OSError, ValueError):
			return None
		return ipaddress.IPv4Address(packed)

	def _check_content_type(self, response):
		content_type = response.headers.get('Content-Type', '')
		media_type = content_type.split(';', 1)[0].strip().lower()
		if not media_type:
			raise ResponseLimitError('Response is missing a Content-Type header')
		if media_type not in self.allowed_content_types:
			raise ResponseLimitError(
				'Content type %s is not allowed for %s input' % (media_type, self.input_format))

	def _read_bounded(self, response):
		declared_length = response.headers.get('Content-Length')
		if declared_length is not None:
			try:
				if int(declared_length) > self.max_bytes:
					raise ResponseLimitError(
						'Response size %s bytes exceeds limit of %s bytes'
						% (declared_length, self.max_bytes))
			except ValueError:
				pass

		chunks = []
		total = 0
		try:
			for chunk in response.iter_content(self.chunk_size):
				if not chunk:
					continue
				total += len(chunk)
				if total > self.max_bytes:
					raise ResponseLimitError(
						'Response size exceeds limit of %s bytes' % (self.max_bytes))
				chunks.append(chunk)
		except ResponseLimitError:
			if hasattr(response, 'close'):
				response.close()
			raise
		return b''.join(chunks)

	def _close_response(self, response):
		if hasattr(response, 'close'):
			response.close()

	def fetch(self, url):
		session = self._get_session()
		headers = {'User-Agent': self.user_agent}
		current_url = url
		redirects = 0

		while True:
			self.ensure_public_target(current_url)
			try:
				response = session.get(
					current_url,
					headers=headers,
					stream=True,
					allow_redirects=False,
					timeout=self.timeout)
			except Exception as e:
				if requests is not None and isinstance(e, requests.Timeout):
					raise ResponseLimitError(
						'Timed out after %s seconds fetching %s' % (self.timeout, current_url))
				raise RemoteFetchError('Failed to fetch %s: %s' % (current_url, e))

			if response.status_code in REDIRECT_STATUSES and 'Location' in response.headers:
				self._close_response(response)
				redirects += 1
				if redirects > self.max_redirects:
					raise ResponseLimitError(
						'Too many redirects (limit %s) fetching %s' % (self.max_redirects, url))
				from urllib.parse import urljoin
				current_url = urljoin(current_url, response.headers['Location'])
				continue

			if response.status_code < 200 or response.status_code >= 300:
				status = response.status_code
				self._close_response(response)
				raise RemoteFetchError(
					'HTTP %d returned for %s' % (status, current_url))

			try:
				self._check_content_type(response)
				content = self._read_bounded(response)
			finally:
				self._close_response(response)
			return content, current_url

	@contextlib.contextmanager
	def open_remote(self, url):
		content, final_url = self.fetch(url)
		stream = BytesIO(content)
		try:
			yield stream, final_url
		finally:
			stream.close()

	def read_transaction(self, url, parser_func, fpath=None):
		label = fpath or url
		with self.open_remote(url) as (stream, final_url):
			try:
				parser_func(stream, label)
			except (KeyboardInterrupt, SystemExit):
				raise
			except RemoteReadError:
				raise
			except Exception as e:
				raise RemoteParseError(
					'Failed to parse remote report %s: %s' % (final_url, e))
