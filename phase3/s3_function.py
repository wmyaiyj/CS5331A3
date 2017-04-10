import requests
import re
import urllib
titleRe = re.compile("<title.*?>(.+?)</title>")
def self_checkIfCanLogin(payload, loginurl, header):
	request = requests.post(loginurl, data=payload, headers=header, verify=False)
	content = request.content.lower().replace(" ", "")
	if ("logout" in content) and (request.status_code == 200):
		return True
	if "session expired" in content:
		return False
	for param in payload:
		print param
		if ("name='"+str(param)+"'" in content) or ('name="'+str(param)+'"' in content):
			return False
	return True
	#else:
	#	return False

def self_checkStillLoggedIn(loginpayload, content):
	content = content.lower().replace(" ", "")
	#if ("logout" in content):
	if "session expired" in content:
		return False
	if ("logout" in content):
		return True
	for param in loginpayload:
		if ("name='"+str(param)+"'" in content) or ('name="'+str(param)+'"' in content):
			if len(content) > 0:
				text_file = open("Output.txt", "w")
				text_file.write(content)
				text_file.close()
			return False
	return True
	#else:
	#	return False
	
def self_post(load, url, header):
	request = requests.post(url, data=load, headers=header, verify=False)
	return request
	
def self_get(load, url, header):
	request = requests.get(url, params=load, headers=header, verify=False)
	return request
	
def self_gotsqlsyntaxerror(content):
	if ("You have an error in your SQL syntax" in content) or ("syntax error" in content.lower()):	
		return True
	return False

def self_hijackSuccessful(initialRequest, newRequest, falseRequest, isSleepCommand, payload, isPostRequest, initialTrip, newTrip, loginpayload={}, param=""):

	if isinstance(payload, unicode):
		payload = payload.encode('ascii','ignore')
	try:
		count = newRequest.content.count(urllib.unquote(payload).replace("+"," "))
		lenthOfDecodedPayload = len(urllib.unquote(payload).replace("+"," "))

		
	except:
		count = 0
		lenthOfDecodedPayload = 0
	print "count of encoded payload: "+str(count)
	print type(str(payload))
	try:
		countBeforeDecode = newRequest.content.count(payload)
	except:
		print "exception"
		countBeforeDecode = 0
		pass
	print payload
	print "count of pure payload: "+str(countBeforeDecode)
	print "pure payload length "+str(len(payload))
	try:
		initialTitle = titleRe.search(initialRequest.content).group(1)
		newTitle = titleRe.search(newRequest.content).group(1)
		falseTitle = titleRe.search(falseRequest.content).group(1)
	except:
		initialTitle = ""
		newTitle = ""
		falseTitle = ""
	print "initial Title: "+str(initialTitle)
	print "new Title: "+str(newTitle)
	print "false Title: "+str(falseTitle)
	try:
		countOfParam = newRequest.content.count(param+"=")
	except:
		countOfParam = 0
	try:
		countOfParam += newRequest.content.count('name= "'+param+'"')
		countOfParam += newRequest.content.count('name = "'+param+'"')
		countOfParam += newRequest.content.count('name="'+param+'"')
	except:
		countOfParam += 0
	print "param is "+param
	print "count of param: "+str(countOfParam)
	print "content length difference: "+ str(abs(len(newRequest.content)-len(initialRequest.content)))
	if newRequest.status_code != 200:
		message = "Status code not 200"
		return [False,message]
	if isSleepCommand and (newTrip-initialTrip)>5:
		message = "Is sleep command and the response time diff larger than 5 second"
		return [True,message]
	else:
		print newTrip
		print initialTrip



	if (not isSleepCommand) and (len(newRequest.content) <= len(initialRequest.content) + 20):
		print len(newRequest.content)
		print len(initialRequest.content)
		message = "Content is the same or even smaller"
		return [False,message]

	if(self_parseURL(initialRequest.url)!=self_parseURL(falseRequest.url)) and (self_parseURL(newRequest.url) == self_parseURL(falseRequest.url)) and (falseRequest.url != "") and (falseRequest.url is not None) and (newRequest.url != "") and (newRequest.url is not None):
		print initialRequest.url
		print falseRequest.url
		print newRequest.url
		message = "Suspect page was redirected to default error page based on url"
		return [False,message]
	if (falseTitle!= initialTitle) and (newTitle == falseTitle):
		message = "Suspect page was redirected to default error page based on url title"
		return [False,message]
	if(falseRequest.content == newRequest.content) or (abs(len(falseRequest.content) - len(newRequest.content)) < 10):
		message = "Content is almost the same with false response content"
		return [False,message]
	if len(newRequest.content)-len(initialRequest.content) < (count*lenthOfDecodedPayload + countOfParam * 20 + countBeforeDecode*len(payload)):
		message = "url encoded payload found in new request, and the content length diff is not enough"
		return [False,message]
	# if(countOfParam>0) and (abs(len(newRequest.content)-len(initialRequest.content)) < countOfParam * 20):
	# 	message = "parameter name found, and the content length diff is not enough"
	# 	return [False,message]
	# if(countBeforeDecode>0) and (abs(len(newRequest.content)-len(initialRequest.content)) < countBeforeDecode*len(payload)):
	# 	message = "pure payload found in new request, and the content length diff is not enough"
	# 	return [False,message]
	#if not isPostRequest:
	#	if self_gotsqlsyntaxerror(newRequest.content):	
	#		message = "SQL Syntax error found"
	#		return [False,message]
	if not self_checkStillLoggedIn(loginpayload,newRequest.content):
		message = "User was logged out"
		return [False,message]
	message = "Successfully hijacked"
	return [True,message]

def self_parseURL(url):
	if "?" in url:
		index = int(url.find("?"))
		return url[0:index]
	else:
		return url