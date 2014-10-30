"""
This script receives a list of Unknown URLs from Palo Alto DB, 
searches for the categories on Fortinet database and generates a bulk-formatted list to be submitted to PA

URLs should be entered one per line.

Test a site website: https://urlfiltering.paloaltonetworks.com/TestASite.aspx
"""

import re
import argparse
from Queue import Queue
import argparse
import urllib
import urllib2
import sys
import multiprocessing
import cookielib
import random
import pickle

parser = argparse.ArgumentParser(description="This script receives a list of Unknown URLs from Palo Alto DB,\nsearches for the categories on Fortinet database and generates a bulk-formatted list to be submitted to PA\n")
parser.add_argument("-f", "--url-list", dest="urlList", help="plain text file containing URLs, one URL per line", metavar="FILE", required=True)
parser.add_argument("-p", "--proxy-list", dest="proxyList", help="proxy list file. Get one at your preferred free public proxy list e.g. www.gatherproxy.com. Format: proxy:port, one per line", metavar="FILE", required=True)
parser.add_argument("-c", "--captcha", dest="captchaCode", help="The value of CaptchaCode", required=False)
parser.add_argument("-s", "--session-id", dest="sessionID", help="The value of LBD_VCID_LoginCaptcha", required=False)

"""" func """
def fetchCategory(proxy, urllist, urlscategorized):
	try:
		url = urllist.pop()
	except:
		print "urllist empty - nothing to do. Returning.."
		return
	
	if url in urlscategorized:
		print "[*] URL already categorized. Doing nothing..."
		return 1 #nothing to do, URL is already categorized, success
	else:
		try:
			print url + ": retrieving category via  " + proxy + " ..."
			cj = cookielib.CookieJar()
			proxy_handler = urllib2.ProxyHandler({'http': 'http://' + proxy})
			opener = urllib2.build_opener(proxy_handler, urllib2.HTTPCookieProcessor(cj))
			user_agent = random.choice(open(USER_AGENT_FILE).readlines()).strip()
			opener.addheaders = [('User-agent', user_agent)]

			req = opener.open("http://www.fortiguard.com/ip_rep/index.php?data=" + url + "?", None, timeout=TIMEOUT)
			html_response = req.read()
		
			regex = '<h3 style="float: left">Category: ([a-zA-Z\- ]+)</h3>'
			reg_match = re.search(regex, html_response, re.MULTILINE)
			print url,
			print reg_match
			if reg_match:
				category = reg_match.group(1)
				print "[*] Found! " + url + " = " + category
 				urlscategorized[url] = category
				return 1
			else:   #couldn't match, assuming proxy issue
				urllist.append(url)
				return 0
		
			print "["  +  str(n) + "] proxy = " + proxy + "\t url = " + url  + "\tmessage = " + category
				
		except Exception, err:
				urllist.append(url)
				print "exception["  +  str(n) + "] proxy = " + proxy + "\t url = " + url  + "\tmessage = " + str(err)
				return 0
				
				
""" main """
args = parser.parse_args()
pickled_file = args.urlList + ".pickled"

TIMEOUT = 10
USER_AGENT_FILE = 'user-agent_list.txt'

manager = multiprocessing.Manager()
urlList = manager.list()
proxyQueue = Queue()
restoredDict = dict()

try:
	with open( args.urlList, 'rb') as h:
		for line in h:
		    li=line.strip()
		    if not li.startswith("#"):
		    	urlList.append(li)
except:
	print "\nError on processing " + str(args.urlList) + ". Exiting..."
	exit()

if not urlList:
	print "[*] " + str(args.urlList) + " is empty. Exiting.."
	exit()

try:
	with open( args.proxyList, "rb") as g:
		for line in g:
		    li=line.strip()
		    if not li.startswith("#"):
		    	proxyQueue.put(li)
except:
	print "\nError on processing " + str(args.proxyList) + ". Exiting..."
	exit()

if proxyQueue.empty():
	print "[*] " + str(args.proxyList) + " is empty. Exiting.."
	exit()

try:
	f=open(pickled_file, 'rb')
	while 1:
		try:
			temp_dict= pickle.load(f)[0]
			restoredDict.update(temp_dict)
		except EOFError:
			break
		except Exception, err:
			print "General Except" + str(err)
			break
	f.close()
	urlsCategorized = manager.dict(restoredDict)
except:
	print "[*] Unable to load " + pickled_file + " (okay for a first run)"
	urlsCategorized = manager.dict()

pool = multiprocessing.Pool(multiprocessing.cpu_count()*10)
while not proxyQueue.empty():
	if urlList:
		proxy_candidate = proxyQueue.get()
		for n in range(0,10):
			pool.apply_async(fetchCategory, args=(proxy_candidate, urlList, urlsCategorized,))
pool.close()
pool.join()	

backupDict = dict(urlsCategorized)

# pickle urlsCategorized
try:
		pickledData = [backupDict]
		with open( pickled_file, "wb" ) as f:
    			pickle.dump( pickledData, f)
except:
		print "[*] Bummer - couldn't pickle. Resume won't be possible (this is weird..)"

# writes the remaining urls that were not processed
try:
		with open(args.urlList, 'w') as f:
			for s in urlList:
				f.write(s + "\n")
		print "[*] Successfully updated " + str(args.urlList)
except:
		print "[*] Error while updating " + str(args.urlList)

manager.shutdown()
del manager