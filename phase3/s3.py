import sys
import urllib
import json
import requests
import time
import copy
from pprint import pprint
from s3_function import self_checkIfCanLogin,self_post,self_get,self_gotsqlsyntaxerror,self_checkStillLoggedIn,self_hijackSuccessful,self_parseURL
from difflib import Differ
import time
jsonform = []
loginPayloadDict = {}
vunlerableUrlWithParam = {}
runname=sys.argv[1:][0]
defaultHeader = {
			"Referer": "https://app5.com/www/index.php",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36"
		}
with open('../s2.json') as file:
	payloads = json.load(file);
with open('../config.json') as file:
	print "--------------loading login information--------------------"
	data = json.load(file)
	for loginurls in data["loginurls"]:
		if loginurls["name"] == runname:
			loginurl = loginurls["loginurl"]
			loginPayload = loginurls["loginpayload"]
			print loginPayload
			if(loginurl in loginPayloadDict):
				payloadList = loginPayloadDict[loginurl]
				payloadList.append(loginPayload)
			else:			
				loginPayloadDict[loginurl] = loginPayload
			
with open("../results/"+runname+'.json') as data_file:
#with open('phase1.json') as data_file:
	print "--------------loading url information--------------------"
	data = json.load(data_file)
	urlsToProcess = data["urls"]
	for urls in data["urls"]:	
		url = urls["url"]
		if (url in loginPayloadDict) and (urls["type"] =="POST") and urls["param"]:	
			urlsToProcess.remove(urls)
			#process login urls firstif url in loginPayloadDict:
			#it's a log in url
			#get all log in accounts and password
			crendentials = loginPayloadDict[url]
			initialLoad = copy.deepcopy(urls["param"])
			#get first log in credential to test is enough
			#assign param to crendentials
			for param in crendentials:
				initialLoad[param] = [crendentials[param]]
			credential = copy.deepcopy(initialLoad)
			#try to log in and get the response content
			loginStatus = self_checkIfCanLogin(credential, url, defaultHeader)
			if not loginStatus:
				print "Login fail, please check your credentials below"
				print url
				print credential
			else:
				#try different payload to test if login has vunlerbility
				
				for param in credential:
					for payload in payloads:
						#replace the login parameter with different payload, test if can log in
						fakeCredential = copy.deepcopy(credential)
						if param in loginPayloadDict[url]:
							print fakeCredential[param][0]
							fakeCredential[param][0] = fakeCredential[param][0] + payload
							loginStatus = self_checkIfCanLogin(fakeCredential, url, defaultHeader)
							if loginStatus:
								#logged in successful, consider hack successfully
								initialUrl = copy.deepcopy(urls)
								initialUrl["param"] = fakeCredential
								jsonform.append(initialUrl)					
								break
				loginPayloadDict[url] = credential
	
	data["urls"] = copy.deepcopy(urlsToProcess)
	
	print"-------------Processing get and required log in-----------------------"
	#process those get parameter with login required
	for urls in data["urls"]:	
		url = urls["url"]
		if(urls["type"]=="GET") and (urls["loginrequired"] == "true") and (url not in loginPayloadDict):
			urlsToProcess.remove(urls)
			initialheader = defaultHeader
			loginurl = urls["loginurl"]
			# Log in first
			# get log in url from config file
			if loginurl in loginPayloadDict:
				#it's a log in url
				credential = loginPayloadDict[loginurl]
				loginpayload = credential					
				with requests.Session() as s:
					print loginpayload
					p = s.post(loginurl, data=loginpayload, verify=False)
					if p.status_code != 200:
						print "Error while log in"
					else:
						# An authorised request.
						initialLoad = copy.deepcopy(urls["param"])							
						start = time.time()
						initialRequest = s.get(url,params = initialLoad, headers=initialheader, verify = False)
						initialContent = initialRequest.content
						initialTrip = time.time() - start
						
						print "-------------------Initial Request---------------------"
						print url
						print initialLoad
						print "----------------------------------------"							
						initialLength = len(initialRequest.content)#int(initialRequest.headers["Content-Length"])
						initialStatus = initialRequest.status_code
						initialEndingUrl = initialRequest.url
						parsedUrl = self_parseURL(initialRequest.url)
						for param in initialLoad:
							if parsedUrl in vunlerableUrlWithParam:
								listOfParam = vunlerableUrlWithParam[parsedUrl]
								if param in listOfParam:
									#this param with this url already identified as vunlerable, skip the rest of the test
									continue
							load = copy.deepcopy(initialLoad)
							if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
								load[param] =  ["'"]
							else:
								load[param][0] =  load[param][0]+"'"
							newurl = url+"?"
							for l in load:
								newurl = newurl+l+"="+load[l][0]+"&"
							newurl = newurl[0:-1]							
							falseRequest = s.get(newurl, headers=initialheader, verify = False)
							if not self_checkStillLoggedIn(loginPayload,falseRequest.content):
								#if logged out after get, try to login again
								p = s.post(loginurl, data=loginpayload, verify=False)
							if self_gotsqlsyntaxerror(falseRequest.content):
								#got sql syntax error hack successful
								#break for loop
								if parsedUrl in vunlerableUrlWithParam:
									listOfParam = vunlerableUrlWithParam[parsedUrl]
									if param not in listOfParam:
										listOfParam.append(param)
								else:
									listOfParam = [param]
									vunlerableUrlWithParam[parsedUrl] = listOfParam
									

									initialUrl = copy.deepcopy(urls)
									initialUrl["param"] = load
									initialUrl["loginpayload"] = loginpayload
									initialUrl["newurl"] = newurl
									jsonform.append(initialUrl)		
								continue
							for payload in payloads:
								if parsedUrl in vunlerableUrlWithParam:
									listOfParam = vunlerableUrlWithParam[parsedUrl]
									if param in listOfParam:
										#this param with this url already identified as vunlerable, skip the rest of the test
										continue
								if payload.endswith('#'):
									#do not do this for get request...
									continue
								ifisSleepCommand = False
								if "sleep" in payload:
									ifisSleepCommand = True
								#replace each parameter with the payload to test
								load = copy.deepcopy(initialLoad)
								#print load[param]
								#print param
								#print type(load[param])
								if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
									load[param] =  [payload]
								else:
									load[param][0] =  load[param][0]+payload
								newurl = url+"?"
								for l in load:
									newurl = newurl+l+"="+load[l][0]+"&"
								newurl = newurl[0:-1]
								start = time.time()
								#r = s.get(url,params = load, headers=header, verify = False)
								r = s.get(newurl, headers=initialheader, verify = False)
								if not self_checkStillLoggedIn(loginPayload,r.content):
									#if logged out after get, try to login again
									p = s.post(loginurl, data=loginpayload, verify=False)
									continue
								newContent = r.content
								trip = time.time() - start
								length = len(r.content)
								status = r.status_code
								newEndingUrl = r.url
								# only if the content lenght is larger, and the status code is 200
								# or the response time is much longger say 5 seconds for Time-based blind SQL injection
								# we consider it's a valid attack
								if self_gotsqlsyntaxerror(r.content):
									#got sql syntax error hack successful
									#break for loop
									parsedUrl = self_parseURL(initialRequest.url)
									if parsedUrl in vunlerableUrlWithParam:
										listOfParam = vunlerableUrlWithParam[parsedUrl]
										if param not in listOfParam:
											listOfParam.append(param)
									else:
										listOfParam = [param]
										vunlerableUrlWithParam[parsedUrl] = listOfParam
										initialUrl = copy.deepcopy(urls)
										initialUrl["param"] = load
										initialUrl["loginpayload"] = loginpayload
										initialUrl["newurl"] = newurl
										jsonform.append(initialUrl)					

										text_file = open("Output.txt", "w")
										text_file.write(newContent)
										text_file.close()
										text_file = open("OutputInitial.txt", "w")
										text_file.write(initialContent)
										text_file.close()
									continue		
								#try:
									#self_hijackSuccessful(initialRequest, newRequest, falseRequest, message =, payload, isPostRequest, initialTrip, newTrip, loginpayload={}, param="")
								resultArray = self_hijackSuccessful(initialRequest,r,falseRequest,ifisSleepCommand,payload,False,initialTrip,trip,loginPayload,param)
								print "------------------result----------------------"
								issuccessful = resultArray[0]
								print resultArray[1]
								print newurl
								#except:
								#	issuccessful = False
								print issuccessful
								if issuccessful:
									initialUrl = copy.deepcopy(urls)
									initialUrl["param"] = load
									initialUrl["loginpayload"] = loginpayload
									initialUrl["newurl"] = newurl
									jsonform.append(initialUrl)					

									text_file = open("Output.txt", "w")
									text_file.write(newContent)
									text_file.close()
									text_file = open("OutputInitial.txt", "w")
									text_file.write(initialContent)
									text_file.close()
									continue

						hackHeader = copy.deepcopy(initialheader)
						hackHeader["referer"] = "some random header"
						requestAfterHeaderChange = s.get(url,params = initialLoad, headers=hackHeader, verify = False)
						hackContentLength = len(requestAfterHeaderChange.content)
						if abs(hackContentLength-initialLength)>20:
							#header may be used to hack
							for payload in payloads:
								hackHeader = copy.deepcopy(initialheader)
								hackHeader["referer"] = payload
								requestAfterHeaderChange = s.get(url,params = initialLoad, headers=hackHeader, verify = False)
								hackContentLength = len(requestAfterHeaderChange.content)
								if hackContentLength == initialLength:
									initialUrl = copy.deepcopy(urls)
									initialUrl["param"] = load
									initialUrl["loginpayload"] = loginpayload
									initialUrl["newurl"] = newurl
									initialUrl["headers"] = hackHeader
									jsonform.append(initialUrl)									
									break
				
	data["urls"] = copy.deepcopy(urlsToProcess)


	print"-------------Processing get and not required log in-----------------------"
	#process those get parameter with out login required
	for urls in data["urls"]:	
		url = urls["url"]
		if(urls["type"]=="GET") and (urls["loginrequired"] == "false") and (url not in loginPayloadDict):
			urlsToProcess.remove(urls)	
			initialLoad = copy.deepcopy(urls["param"])	
			initialheader = defaultHeader		
			# An authorised request.
			initialLoad = copy.deepcopy(urls["param"])							
			start = time.time()
			initialRequest = requests.get(url, params=initialLoad, headers=initialheader, verify=False)# s.get(url,params = initialLoad, headers=header, verify = False)
			initialContent = initialRequest.content
			initialTrip = time.time() - start
			print "-------------------Initial Request---------------------"
			print initialRequest.headers
			print url
			print initialLoad
			print "----------------------------------------"							
			initialLength = len(initialRequest.content)#int(initialRequest.headers["Content-Length"])
			initialStatus = initialRequest.status_code
			initialEndingUrl = initialRequest.url
			parsedUrl = self_parseURL(initialEndingUrl)
			for param in initialLoad:	
				if parsedUrl in vunlerableUrlWithParam:
					listOfParam = vunlerableUrlWithParam[parsedUrl]
					if param in listOfParam:
						#this param with this url already identified as vunlerable, skip the rest of the test
						continue
				load = copy.deepcopy(initialLoad)
				if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
					load[param] =  ["'"]
				else:
					load[param][0] =  load[param][0]+"'"
				newurl = url+"?"
				for l in load:
					newurl = newurl+l+"="+load[l][0]+"&"
				newurl = newurl[0:-1]							
				falseRequest = requests.get(newurl, headers=initialheader, verify = False)
				if self_gotsqlsyntaxerror(falseRequest.content):
					#got sql syntax error hack successful
					#break for loop
					if parsedUrl in vunlerableUrlWithParam:
						listOfParam = vunlerableUrlWithParam[parsedUrl]
						if param not in listOfParam:
							listOfParam.append(param)
					else:
						listOfParam = [param]
						vunlerableUrlWithParam[parsedUrl] = listOfParam
						
						initialUrl = copy.deepcopy(urls)
						initialUrl["param"] = load
						initialUrl["newurl"] = newurl
						jsonform.append(initialUrl)		
					continue
				for payload in payloads:
					if parsedUrl in vunlerableUrlWithParam:
						listOfParam = vunlerableUrlWithParam[parsedUrl]
						if param in listOfParam:
							#this param with this url already identified as vunlerable, skip the rest of the test
							continue
					if payload.endswith('#'):
						#do not do this for get request...
						continue
					ifisSleepCommand = False
					if "sleep" in payload:
						ifisSleepCommand = True
					#replace each parameter with the payload to test
					load = copy.deepcopy(initialLoad)
					#print load[param]
					#print param
					#print type(load[param])
					if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
						load[param] =  [payload]
					else:
						load[param][0] =  load[param][0]+payload
					newurl = url+"?"
					for l in load:
						newurl = newurl+l+"="+load[l][0]+"&"
					newurl = newurl[0:-1]
					start = time.time()
					#r = s.get(url,params = load, headers=header, verify = False)
					r = requests.get(newurl, headers=initialheader, verify = False)
					newContent = r.content
					trip = time.time() - start
					if self_gotsqlsyntaxerror(r.content):
						#got sql syntax error hack successful
						#break for loop
						parsedUrl = self_parseURL(initialRequest.url)
						if parsedUrl in vunlerableUrlWithParam:
							listOfParam = vunlerableUrlWithParam[parsedUrl]
							if param not in listOfParam:
								listOfParam.append(param)
						else:
							listOfParam = [param]
							vunlerableUrlWithParam[parsedUrl] = listOfParam
							initialUrl = copy.deepcopy(urls)
							initialUrl["param"] = load
							initialUrl["newurl"] = newurl
							jsonform.append(initialUrl)					

							text_file = open("Output.txt", "w")
							text_file.write(newContent)
							text_file.close()
							text_file = open("OutputInitial.txt", "w")
							text_file.write(initialContent)
							text_file.close()
						continue
					print "-----------Result----------------"
					try:
						resultArray = self_hijackSuccessful(initialRequest,r,falseRequest,ifisSleepCommand, payload,False,initialTrip,trip,{},param)
						issuccessful = resultArray[0]
						print resultArray[1]
					except:
						issuccessful = False
					print newurl
					print issuccessful
					if issuccessful:
						initialUrl = copy.deepcopy(urls)
						initialUrl["param"] = load
						initialUrl["newurl"] = newurl
						jsonform.append(initialUrl)		

						text_file = open("Output.txt", "w")
						text_file.write(newContent)
						text_file.close()
						text_file = open("OutputInitial.txt", "w")
						text_file.write(initialContent)
						text_file.close()
						continue
			
			hackHeader = copy.deepcopy(initialheader)
			hackHeader["referer"] = "some random header"
			requestAfterHeaderChange = requests.get(url,params = initialLoad, headers=hackHeader, verify = False)
			hackContentLength = len(requestAfterHeaderChange.content)
			if abs(hackContentLength-initialLength)>20:
				#header may be used to hack
				for payload in payloads:
					hackHeader = copy.deepcopy(initialheader)
					hackHeader["referer"] = payload
					requestAfterHeaderChange = requests.get(url,params = initialLoad, headers=hackHeader, verify = False)
					hackContentLength = len(requestAfterHeaderChange.content)
					if hackContentLength == initialLength:
						initialUrl = copy.deepcopy(urls)
						initialUrl["param"] = load
						initialUrl["newurl"] = newurl
						initialUrl["headers"] = hackHeader
						jsonform.append(initialUrl)	
						break	
	data["urls"] = copy.deepcopy(urlsToProcess)
									
		
	print"-------------Processing post and not required log in-----------------------"
	#process those post parameter with out login required
	for urls in data["urls"]:	
		url = urls["url"]
		initialheader = defaultHeader
		if(urls["type"]=="POST") and (urls["loginrequired"] == "false") and (url not in loginPayloadDict):
			urlsToProcess.remove(urls)			
			# An authorised request.
			initialLoad = copy.deepcopy(urls["param"])	
			# put some initial value to the post
			for param in initialLoad:
				if (not initialLoad[param]) | (initialLoad[param][0] is None) | (initialLoad[param][0] == "") | (initialLoad[param][0] == "None"):
					initialLoad[param] =  ["a"]						
			start = time.time()
			initialRequest = requests.post(url, params=initialLoad, headers=defaultHeader, verify=False)
			initialContent = initialRequest.content
			initialTrip = time.time() - start
			print "-------------------Initial Request---------------------"
			print initialRequest.headers
			print url
			print initialLoad
			print "----------------------------------------"							
			initialLength = len(initialRequest.content)#int(initialRequest.headers["Content-Length"])
			initialStatus = initialRequest.status_code
			initialEndingUrl = initialRequest.url
			parsedUrl = self_parseURL(initialRequest.url)
			for param in initialLoad:
				if parsedUrl in vunlerableUrlWithParam:
					listOfParam = vunlerableUrlWithParam[parsedUrl]
					if param in listOfParam:
						#this param with this url already identified as vunlerable, skip the rest of the test
						continue
				load = copy.deepcopy(initialLoad)				
				if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
					load[param] =  ["'"]
				else:
					load[param][0] = load[param][0]+"'"					
				falseRequest = requests.post(url, data=load, headers=defaultHeader, verify=False)

				if self_gotsqlsyntaxerror(falseRequest.content):
					#got sql syntax error hack successful
					#break for loop
					parsedUrl = self_parseURL(initialRequest.url)
					if parsedUrl in vunlerableUrlWithParam:
						listOfParam = vunlerableUrlWithParam[parsedUrl]
						if param not in listOfParam:
							listOfParam.append(param)
					else:
						listOfParam = [param]
						vunlerableUrlWithParam[parsedUrl] = listOfParam
						
						initialUrl = copy.deepcopy(urls)
						initialUrl["param"] = load
						jsonform.append(initialUrl)		
					continue
				for payload in payloads:
					if parsedUrl in vunlerableUrlWithParam:
						listOfParam = vunlerableUrlWithParam[parsedUrl]
						if param in listOfParam:
							#this param with this url already identified as vunlerable, skip the rest of the test
							continue
					#replace each parameter with the payload to test
					#only test blind
					#only test blind sql for post
					ifisSleepCommand = False
					if "sleep" in payload:
						ifisSleepCommand = True
					load = copy.deepcopy(initialLoad)
					#print load[param]
					#print param
					#print type(load[param])
					if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
						load[param] =  [payload]
					else:
						load[param][0] = payload
					start = time.time()
					print "-----------Result----------------"
					print load
					print start
					print time.strftime("%H:%M:%S")
					r = requests.post(url, data=load, headers=defaultHeader, verify=False)
					newContent = r.content
					trip = time.time() - start
					if self_gotsqlsyntaxerror(r.content):
						#got sql syntax error hack successful
						#break for loop
						parsedUrl = self_parseURL(initialRequest.url)
						if parsedUrl in vunlerableUrlWithParam:
							listOfParam = vunlerableUrlWithParam[parsedUrl]
							if param not in listOfParam:
								listOfParam.append(param)
						else:
							listOfParam = [param]
							vunlerableUrlWithParam[parsedUrl] = listOfParam
							initialUrl = copy.deepcopy(urls)
							initialUrl["param"] = load
							initialUrl["newurl"] = newurl
							jsonform.append(initialUrl)					

							text_file = open("Output.txt", "w")
							text_file.write(newContent)
							text_file.close()
							text_file = open("OutputInitial.txt", "w")
							text_file.write(initialContent)
							text_file.close()
						continue	
					length = len(r.content)
					
					print time.strftime("%H:%M:%S")
					print trip
					print time.time()

					print "-----------Result----------------"
					try:
						resultArray = self_hijackSuccessful(initialRequest,r,falseRequest,ifisSleepCommand,payload,True,initialTrip,trip,{},param)
						issuccessful = resultArray[0]
						print resultArray[1]
					except:
						issuccessful = False
					print issuccessful
					if issuccessful:
						if parsedUrl in vunlerableUrlWithParam:
							listOfParam = vunlerableUrlWithParam[parsedUrl]
							if param not in listOfParam:
								listOfParam.append(param)
						else:
							listOfParam = [param]
							vunlerableUrlWithParam[parsedUrl] = listOfParam
							initialUrl = copy.deepcopy(urls)
							initialUrl["param"] = load
							jsonform.append(initialUrl)

							text_file = open("Output.txt", "w")
							text_file.write(newContent)
							text_file.close()
							text_file = open("OutputInitial.txt", "w")
							text_file.write(initialContent)
							text_file.close()
						continue
					

			hackHeader = copy.deepcopy(defaultHeader)
			hackHeader["referer"] = "some random header"
			requestAfterHeaderChange = requests.post(url, data=initialLoad, headers=hackHeader, verify=False)
			hackContentLength = len(requestAfterHeaderChange.content)
			if abs(hackContentLength-initialLength)>20:
				#header may be used to hack
				for payload in payloads:
					hackHeader = copy.deepcopy(initialheader)
					hackHeader["referer"] = payload
					requestAfterHeaderChange = requests.post(url, data=initialLoad, headers=hackHeader, verify=False)
					hackContentLength = len(requestAfterHeaderChange.content)
					if hackContentLength == initialLength:
						if parsedUrl in vunlerableUrlWithParam:
							listOfParam = vunlerableUrlWithParam[parsedUrl]
							if param not in listOfParam:
								listOfParam.append(param)
						else:
							listOfParam = [param]
							vunlerableUrlWithParam[parsedUrl] = listOfParam
							initialUrl = copy.deepcopy(urls)
							initialUrl["param"] = load
							initialUrl["headers"] = hackHeader
							jsonform.append(initialUrl)
						break
	data["urls"] = copy.deepcopy(urlsToProcess)
	
	print"-------------Processing post and required log in-----------------------"
	#process those post parameter with login required
	for urls in data["urls"]:	
		url = urls["url"]
		initialheader = defaultHeader
		if(urls["type"]=="POST") and (urls["loginrequired"] == "true") and (url not in loginPayloadDict):
			urlsToProcess.remove(urls)
			loginurl = urls["loginurl"]
			# Log in first
			# get log in url from config file
			if loginurl in loginPayloadDict:
				#it's a log in url
				credential = loginPayloadDict[loginurl]
				loginpayload = credential					
				with requests.Session() as s:
					print loginpayload
					p = s.post(loginurl, data=loginpayload, verify=False)
					if p.status_code != 200:
						print "Error while log in"
					else:
						# An authorised request.
						initialLoad = copy.deepcopy(urls["param"])	
						# put some initial value to the post
						for param in initialLoad:
							print initialLoad
							print param
							print initialLoad[param]
							if (not initialLoad[param]) | (initialLoad[param][0] is None) | (initialLoad[param][0] == "") | (initialLoad[param][0] == "None"):
								initialLoad[param] =  ["a"]							
						start = time.time()
						initialRequest = s.post(url,data = initialLoad, headers=defaultHeader, verify = False)
						initialContent = initialRequest.content
						initialTrip = time.time() - start
						print "-------------------Initial Request---------------------"
						print initialRequest.headers
						print url
						print initialLoad
						print "----------------------------------------"							
						initialLength = len(initialRequest.content)#int(initialRequest.headers["Content-Length"])
						initialStatus = initialRequest.status_code
						initialEndingUrl = initialRequest.url
						parsedUrl = self_parseURL(initialRequest.url)
						for param in initialLoad:			
							if parsedUrl in vunlerableUrlWithParam:
								listOfParam = vunlerableUrlWithParam[parsedUrl]
								if param in listOfParam:
									#this param with this url already identified as vunlerable, skip the rest of the test
									continue			
							load = copy.deepcopy(initialLoad)				
							if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
								load[param] =  ["'"]
							else:
								load[param][0] = load[param][0]+"'"					
							falseRequest = s.post(url,data = load, headers=defaultHeader, verify = False)
							if not self_checkStillLoggedIn(loginPayload,falseRequest.content):
								#if logged out after get, try to login again
								p = s.post(loginurl, data=loginpayload, verify=False)
							if self_gotsqlsyntaxerror(falseRequest.content):
								#got sql syntax error hack successful
								#break for loop
								parsedUrl = self_parseURL(initialRequest.url)
								if parsedUrl in vunlerableUrlWithParam:
									listOfParam = vunlerableUrlWithParam[parsedUrl]
									if param not in listOfParam:
										listOfParam.append(param)
								else:
									listOfParam = [param]
									vunlerableUrlWithParam[parsedUrl] = listOfParam
									
									initialUrl = copy.deepcopy(urls)
									initialUrl["param"] = load
									initialUrl["loginpayload"] = loginpayload
									jsonform.append(initialUrl)	
								continue
							for payload in payloads:
								if parsedUrl in vunlerableUrlWithParam:
									listOfParam = vunlerableUrlWithParam[parsedUrl]
									if param in listOfParam:
										#this param with this url already identified as vunlerable, skip the rest of the test
										continue
								#only test blind sql for post								
								ifisSleepCommand = False
								if "sleep" in payload:
									ifisSleepCommand = True
								#replace each parameter with the payload to test
								load = copy.deepcopy(initialLoad)
								#print load[param]
								#print param
								#print type(load[param])
								if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
									load[param] =  [payload]
								else:
									load[param][0] =  payload
								start = time.time()
								r = s.post(url,data = load, headers=defaultHeader, verify = False)

								if not self_checkStillLoggedIn(loginPayload,r.content):
									#if logged out after get, try to login again
									p = s.post(loginurl, data=loginpayload, verify=False)
								if self_gotsqlsyntaxerror(r.content):
									#got sql syntax error hack successful
									#break for loop
									parsedUrl = self_parseURL(initialRequest.url)
									if parsedUrl in vunlerableUrlWithParam:
										listOfParam = vunlerableUrlWithParam[parsedUrl]
										if param not in listOfParam:
											listOfParam.append(param)
									else:
										listOfParam = [param]
										vunlerableUrlWithParam[parsedUrl] = listOfParam
										initialUrl = copy.deepcopy(urls)
										initialUrl["param"] = load
										initialUrl["loginpayload"] = loginpayload
										initialUrl["newurl"] = newurl
										jsonform.append(initialUrl)					

										text_file = open("Output.txt", "w")
										text_file.write(newContent)
										text_file.close()
										text_file = open("OutputInitial.txt", "w")
										text_file.write(initialContent)
										text_file.close()
									continue	
								newContent = r.content
								trip = time.time() - start
								length = len(r.content)
								try:
									resultArray = self_hijackSuccessful(initialRequest,r,falseRequest,ifisSleepCommand,payload,True,initialTrip,trip,loginPayload,param)
									issuccessful = resultArray[0]
									print resultArray[1]
								except:
									issuccessful = False

								print "-----------Result----------------"
								print issuccessful
								if issuccessful:
									if parsedUrl in vunlerableUrlWithParam:
										listOfParam = vunlerableUrlWithParam[parsedUrl]
										if param not in listOfParam:
											listOfParam.append(param)
									else:
										listOfParam = [param]
										vunlerableUrlWithParam[parsedUrl] = listOfParam
										initialUrl = copy.deepcopy(urls)
										initialUrl["param"] = load
										initialUrl["loginpayload"] = loginpayload
										jsonform.append(initialUrl)

										text_file = open("Output.txt", "w")
										text_file.write(newContent)
										text_file.close()
										text_file = open("OutputInitial.txt", "w")
										text_file.write(initialContent)
										text_file.close()
									continue

						hackHeader = copy.deepcopy(defaultHeader)
						hackHeader["referer"] = "some random header"
						requestAfterHeaderChange = s.post(url, data=initialLoad, headers=hackHeader, verify=False)
						hackContentLength = len(requestAfterHeaderChange.content)
						if abs(hackContentLength-initialLength)>20:
							#header may be used to hack
							for payload in payloads:
								hackHeader = copy.deepcopy(initialheader)
								hackHeader["referer"] = payload
								requestAfterHeaderChange = s.post(url, data=initialLoad, headers=hackHeader, verify=False)
								hackContentLength = len(requestAfterHeaderChange.content)
								if hackContentLength == initialLength:
									if parsedUrl in vunlerableUrlWithParam:
										listOfParam = vunlerableUrlWithParam[parsedUrl]
										if param not in listOfParam:
											listOfParam.append(param)
									else:
										listOfParam = [param]
										vunlerableUrlWithParam[parsedUrl] = listOfParam
										initialUrl = copy.deepcopy(urls)
										initialUrl["param"] = load
										initialUrl["loginpayload"] = loginpayload
										initialUrl["headers"] = hackHeader
										jsonform.append(initialUrl)
									break
	data["urls"] = copy.deepcopy(urlsToProcess)

	
with open("../results/phase3_output_"+runname+".json",'w') as outfile:	
	json.dump(jsonform,outfile,indent=2)
print "==========================Scan Finished========================================"