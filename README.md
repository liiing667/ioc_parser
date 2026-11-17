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

## Remote reports

HTTP(S) inputs are read through a single constrained transaction implemented in
`iocp/Remote.py`:

* Only `http` and `https` URLs are accepted, and every request target - including
  each redirect hop - must resolve to a public IP address. Loopback, link-local,
  private, reserved and multicast ranges are rejected, so internal services (for
  example the cloud metadata endpoint) cannot be read.
* Redirects are followed manually with a fixed budget (default 3), each request
  uses an explicit timeout (default 10s), the response content type must match
  the selected input format, and downloads are streamed with a size cap
  (default 10 MiB).
* Failures are raised as categorized exceptions instead of being mixed into the
  generic error output:
  * `Remote.PrivateTargetError` (`private_target`) - non-public target or disallowed scheme
  * `Remote.ResponseLimitError` (`response_limit`) - timeout, too many redirects, oversize body or bad content type
  * `Remote.RemoteFetchError` (`fetch_error`) - DNS failure, connection error or bad HTTP status
  * `Remote.RemoteParseError` (`parse_error`) - the downloaded report could not be parsed

All limits can be tuned through `Remote.RemoteFetcher` constructor parameters.
Local file and directory parsing is unchanged.
