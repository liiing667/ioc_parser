import json
import os

from iocp.Parser import Parser, CollectingHandler
from iocp import Output


FIXTURE = os.path.join(
	os.path.dirname(__file__), 'fixtures', 'boundary_report.txt'
)


def test_parse_txt_file_emits_records_with_evidence_offsets():
	handler = CollectingHandler()
	parser = Parser(
		input_format='txt',
		dedup=True,
		output_handler=handler,
	)
	parser.parse(FIXTURE)

	records = handler.records
	assert records
	text = open(FIXTURE, encoding='utf-8').read()
	for record in records:
		assert set(record) >= {
			'path', 'page', 'type', 'match', 'raw', 'start', 'end'
		}
		assert text[record['start']:record['end']] == record['raw']
		assert record['page'] == 1


def test_csv_and_json_handlers_keep_legacy_columns(capsys):
	parser = Parser(input_format='txt', output_format='csv')
	parser.parse(FIXTURE)
	csv_lines = [
		line for line in capsys.readouterr().out.splitlines() if line
	]
	assert csv_lines
	for line in csv_lines:
		assert len(line.split(',')) >= 4

	parser = Parser(input_format='txt', output_format='json')
	parser.parse(FIXTURE)
	json_lines = [
		line for line in capsys.readouterr().out.splitlines() if line
	]
	assert json_lines
	for line in json_lines:
		payload = json.loads(line)
		assert set(payload) == {'path', 'file', 'page', 'type', 'match'}


def test_all_output_formats_remain_constructible():
	for fmt in Output.OUTPUT_FORMATS:
		handler = Output.getHandler(fmt)
		assert hasattr(handler, 'print_match')
		handler.print_header('report.txt')
		handler.print_match('report.txt', 1, 'Host', 'evil.example.com', record=None)
		handler.print_footer('report.txt')
