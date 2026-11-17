# ioc-parser
IOC Parser is a tool to extract indicators of compromise from security reports in PDF format. A good collection of APT related reports with many IOCs can be found here: [APTNotes](https://github.com/kbandla/APTnotes).

## Usage
**iocp [-h] [-p INI] [-i FORMAT] [-o FORMAT] [-d] [-l LIB] FILE**
* *FILE* File/directory path to report(s)
* *-p INI* Pattern file
* *-i FORMAT* Input format (pdf/txt/html)
* *-o FORMAT* Output format (csv/json/yara)
* *-d* Deduplicate matches
* *-l LIB* Parsing library

## Installation
**pip install ioc_parser**

## Requirements
One of the following PDF parsing libraries:
* [PyPDF2](https://github.com/mstamy2/PyPDF2) - *pip install pypdf2*
* [pdfminer](https://github.com/euske/pdfminer) - *pip install pdfminer*

For HTML parsing support:
* [BeautifulSoup](http://www.crummy.com/software/BeautifulSoup/) - *pip install beautifulsoup4*

For HTTP(S) support:
* [requests](http://docs.python-requests.org/en/latest/) - *pip install requests*

## Whitelists
Whitelists live in `iocp/data/whitelists/whitelist_<TYPE>.ini`, one file per
IOC type (`Host`, `URL`, `IP`, `Email`, ...). Each entry explicitly declares
its match semantics and only applies to the IOC type of its file:

```
exact:example.com       # full-string match (case-insensitive)
suffix:.example.com     # string suffix, e.g. www.example.com but not example.com
pattern:^https?://(www\.)?example\.com/   # regex search, anchor it yourself
```

Blank lines and `#` comments are ignored. Loading fails closed: duplicate or
conflicting entries, unknown kinds, invalid regexes and unknown IOC types
abort the load with a `WhitelistError` instead of silently allowing anything.

Legacy whitelist files (one unanchored regex per line) must be migrated
before they load; domain-shaped entries are tightened to `exact` + `suffix`
so lookalikes such as `evil-example.com` no longer pass:

```
python -m iocp.Whitelist LEGACY_WHITELIST_DIR OUT_DIR
```

Run the whitelist test matrix with `python -m pytest -q`.
