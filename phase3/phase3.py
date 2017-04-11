import json
import sys
import copy
import time
import urllib
import requests
import Injection from inj.py


defaultHeader = {
			"Referer": "https://app4.com/index.php",
			"User-Agent": "Scrapy/1.3.3 (+http://scrapy.org)"
		}

with open('../phase2/phase2.json') as file:
	phase2_payload = json.load(file);

with open('../info.json') as file:
	login_info = json.load(file)

with open("../results/"+app_user+".json") as file:
	injection_info = json.load(file)
	
NewInjection = Injection(phase2_payload, login_info["login_info"], injection_info["urls"])


with open(app_user+"_output.json",'w') as file:	
	json.dump(NewInjection.finalOutput,file,indent=2)
