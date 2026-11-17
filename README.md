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

## Extraction behavior
* URL/Host matches are trimmed of sentence punctuation and unmatched trailing brackets, so adjacent indicators separated by commas or parentheses are reported individually.
* Overlapping indicators follow a type priority (e.g. a `Filepath` suppresses the embedded `Filename`, a `URL` suppresses the embedded `Host`/`IP`).
* With `-d`, indicators are deduplicated after normalization (defang refanging, case folding), not only on exact string equality.
* Each parsed record keeps its raw evidence text and character offsets; programmatic callers can use `Parser.extract_text(text)`.

## Tests
**python -m pytest -q**

## Requirements
One of the following PDF parsing libraries:
* [PyPDF2](https://github.com/mstamy2/PyPDF2) - *pip install pypdf2*
* [pdfminer](https://github.com/euske/pdfminer) - *pip install pdfminer*

For HTML parsing support:
* [BeautifulSoup](http://www.crummy.com/software/BeautifulSoup/) - *pip install beautifulsoup4*

For HTTP(S) support:
* [requests](http://docs.python-requests.org/en/latest/) - *pip install requests*
