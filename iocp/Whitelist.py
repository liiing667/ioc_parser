import glob
import os
import re

#: Match semantics an allowlist entry may declare.
KINDS = ('exact', 'suffix', 'pattern')

#: Legacy lines shaped like ``acm\.org$`` mean "this domain and its
#: subdomains" and are tightened to exact + suffix entries on migration.
_LEGACY_DOMAIN = re.compile(r'^(?P<domain>(?:[A-Za-z0-9\-]+\\\.)+[A-Za-z0-9\-]+)\$$')

#: Legacy lines shaped like ``@example.com`` whitelist a mail domain and
#: are tightened to a suffix entry on migration.
_LEGACY_MAILDOMAIN = re.compile(r'^(?P<domain>@[A-Za-z0-9.\-]+)$')

_DOMAIN_CHARS = re.compile(r'^[A-Za-z0-9.\-]+$')


class WhitelistError(ValueError):
	"""Raised when an allowlist is invalid.

	Loading fails closed: any conflict or malformed entry aborts the whole
	load so a broken allowlist can never silently widen what is allowed.
	"""


class Entry(object):
	"""A single allowlist entry with explicit scope, bound to one IOC type."""

	__slots__ = ('ind_type', 'kind', 'text', 'source', '_regex')

	def __init__(self, ind_type, kind, text, source):
		self.ind_type = ind_type
		self.kind = kind
		self.text = text
		self.source = source
		self._regex = None
		if kind == 'pattern':
			try:
				self._regex = re.compile(text)
			except re.error as e:
				raise WhitelistError('%s: invalid pattern %r: %s' % (source, text, e))

	def matches(self, candidate):
		if self.kind == 'exact':
			return candidate.casefold() == self.text.casefold()
		if self.kind == 'suffix':
			return candidate.casefold().endswith(self.text.casefold())
		return self._regex.search(candidate) is not None

	def _norm(self):
		return self.text if self.kind == 'pattern' else self.text.casefold()


def parse_line(line, source='<string>'):
	"""Parse one scoped allowlist line into a (kind, value) tuple.

	Returns None for blank lines and comments. Raises WhitelistError on
	anything else malformed so bad input fails closed at load time.
	"""
	text = line.strip()
	if not text or text.startswith('#'):
		return None

	kind, sep, value = text.partition(':')
	if not sep:
		raise WhitelistError(
			'%s: missing "<kind>:" prefix (exact/suffix/pattern): %r'
			' -- legacy whitelist lines must be migrated, see'
			' "python -m iocp.Whitelist"' % (source, text))

	kind = kind.strip().lower()
	if kind not in KINDS:
		raise WhitelistError(
			'%s: unknown kind %r, expected one of %s' % (source, kind, ', '.join(KINDS)))

	value = value.strip()
	if not value:
		raise WhitelistError('%s: empty value for kind %r' % (source, kind))

	return kind, value


class Whitelist(object):
	"""Scoped allowlist: entries declare exact/suffix/pattern semantics and
	are only ever consulted for the IOC type they are bound to."""

	def __init__(self, valid_types=None):
		self.valid_types = set(valid_types) if valid_types is not None else None
		self.entries = {}

	def add(self, ind_type, kind, text, source='<string>'):
		if self.valid_types is not None and ind_type not in self.valid_types:
			raise WhitelistError(
				'%s: entry bound to unknown IOC type %r' % (source, ind_type))

		entry = Entry(ind_type, kind, text, source)
		entries = self.entries.setdefault(ind_type, [])
		norm = entry._norm()
		for existing in entries:
			if existing._norm() != norm:
				continue
			if existing.kind == kind:
				raise WhitelistError(
					'%s: duplicate of %s: %s:%s' % (source, existing.source, kind, text))
			raise WhitelistError(
				'%s: conflicts with %s: value %r declared as both %r and %r'
				% (source, existing.source, text, existing.kind, kind))
		entries.append(entry)
		return entry

	def is_whitelisted(self, ind_type, candidate):
		"""True only if an entry bound to ind_type allows the candidate.

		Types without any entries fail closed: nothing is whitelisted.
		"""
		for entry in self.entries.get(ind_type, ()):
			if entry.matches(candidate):
				return True
		return False

	def load_file(self, fpath):
		ind_type = os.path.splitext(os.path.basename(fpath))[0].split('_', 1)[1]
		with open(fpath) as f:
			for lineno, raw in enumerate(f, 1):
				source = '%s:%d' % (fpath, lineno)
				parsed = parse_line(raw, source)
				if parsed is None:
					continue
				self.add(ind_type, parsed[0], parsed[1], source)
		return self

	def load_dir(self, basedir):
		searchdir = os.path.join(basedir, 'whitelist_*.ini')
		for fpath in sorted(glob.glob(searchdir)):
			self.load_file(fpath)
		return self


def load(basedir, valid_types=None):
	return Whitelist(valid_types=valid_types).load_dir(basedir)


def migrate_legacy_line(line):
	"""Convert one legacy (unanchored regex) whitelist line to scoped lines.

	Domain-shaped entries are tightened to exact + suffix semantics so
	lookalikes such as evil-example.com no longer pass; anything else is
	preserved verbatim as an explicit pattern entry. Returns a list of
	scoped lines, or None for blank input.
	"""
	text = line.strip()
	if not text:
		return None

	match = _LEGACY_DOMAIN.match(text)
	if match:
		domain = match.group('domain').replace('\\.', '.')
		if _DOMAIN_CHARS.match(domain):
			return ['exact:%s' % domain, 'suffix:.%s' % domain]

	match = _LEGACY_MAILDOMAIN.match(text)
	if match:
		return ['suffix:%s' % match.group('domain')]

	return ['pattern:%s' % text]


def migrate_legacy_file(src_path, dst_path):
	"""Migrate one legacy whitelist file to the scoped format."""
	lines = []
	with open(src_path) as f:
		for raw in f:
			migrated = migrate_legacy_line(raw)
			if migrated:
				lines.extend(migrated)

	header = [
		'# Migrated from legacy whitelist %s -- review before relying on it.' % os.path.basename(src_path),
		'# Format per line: <kind>:<value> with kind = exact | suffix | pattern.',
	]
	with open(dst_path, 'w') as f:
		f.write('\n'.join(header + lines))
		if header or lines:
			f.write('\n')
	return lines


def migrate_legacy_dir(src_dir, dst_dir):
	"""Migrate every whitelist_*.ini file from src_dir into dst_dir."""
	if not os.path.isdir(dst_dir):
		os.makedirs(dst_dir)
	migrated = []
	searchdir = os.path.join(src_dir, 'whitelist_*.ini')
	for src_path in sorted(glob.glob(searchdir)):
		dst_path = os.path.join(dst_dir, os.path.basename(src_path))
		migrate_legacy_file(src_path, dst_path)
		migrated.append(dst_path)
	return migrated


if __name__ == '__main__':
	import sys
	if len(sys.argv) != 3:
		sys.exit('usage: python -m iocp.Whitelist LEGACY_WHITELIST_DIR OUT_DIR')
	for path in migrate_legacy_dir(sys.argv[1], sys.argv[2]):
		print('migrated -> %s' % path)
