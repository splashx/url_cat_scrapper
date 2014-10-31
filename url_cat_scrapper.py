"""
This script receives a list of URLs, searches for the category on Fortinet database
It uses a list of http proxy to bypass Fortigaurd's limit on 10 requests per minute, 200 per hour, 500 per day.

Tested: with a list of 400 open proxies, 3000 URLs can be categorized in 10min.

URLs should be entered one per line.

# cleanup file from PA:
# $ grep ^URL domains_20141021-30.txt | cut -f2 -d\" | cut -f1 -d\/  | grep -Ev "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u | head
"""
import os
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
import shutil

parser = argparse.ArgumentParser(description="This script receives a list of Unknown URLs from Palo Alto DB,\nsearches for the categories on Fortinet database and generates a bulk-formatted list to be submitted to PA\n")
parser.add_argument("-f", "--url-list", dest="urlList", help="plain text file containing URLs, one URL per line", metavar="FILE", required=True)
parser.add_argument("-p", "--proxy-list", dest="proxyList", help="proxy list file. Get one at your preferred free public proxy list e.g. www.gatherproxy.com. Format: proxy:port, one per line", metavar="FILE", required=True)
parser.add_argument("-c", "--captcha", dest="captchaCode", help="The value of CaptchaCode", required=False)
parser.add_argument("-s", "--session-id", dest="sessionID", help="The value of LBD_VCID_LoginCaptcha", required=False)

"""" func """
# pickle a object. WARNING: this will overwrite the dst file!
def pickleObject(Object, pickledFile):
	try:
			pickledData = [Object]
			with open( pickledFile, "wb" ) as f:
	    			pickle.dump( pickledData, f)
				print "[*] Pickled to "  + pickledFile + "."	
	except:
			print "[I] Bummer - couldn't pickle to "  + pickledFile + ". Resume won't be possible (this is weird..)"	

# check if a file exists, if not creates it / "touch" 
def checkFileExistence(filename):   
	try:
		if not os.path.isfile(filename):
			print "[*] " + filename + " not found. Touching " + filename + " ..."
			f=open(filename, "a")
			f.close()
			return 1
		else:
			print "[I] " + filename + " found. Skipping touch."
			return 1
	except:
		print "[I] Failed to create " + filename + ". Write access?"
		return 0


def fetchCategory(proxy, urllist, urlscategorized, categorizedurlsfromdb):
	try:
		url = urllist.pop()
	except:
		#print "[I] Urllist empty - nothing to do. Returning.."
		return 0
	
	if url in categorizedurlsfromdb:
		print "[*] "+url+": URL already categorized. Doing nothing..."
		return 1 #nothing to do, URL is already categorized, success
	else:
		try:
			print "[*] " + url + ": retrieving category via  " + proxy + " ..."
			cj = cookielib.CookieJar()
			proxy_handler = urllib2.ProxyHandler({'http': 'http://' + proxy})
			opener = urllib2.build_opener(proxy_handler, urllib2.HTTPCookieProcessor(cj))
			user_agent = random.choice(open(USER_AGENT_FILE).readlines()).strip()
			opener.addheaders = [('User-agent', user_agent)]

			req = opener.open("http://www.fortiguard.com/ip_rep/index.php?data=" + url + "?", None, timeout=TIMEOUT)
			html_response = req.read()
		
			regex = '<h3 style="float: left">Category: ([a-zA-Z\- ]+)</h3>'
			reg_match = re.search(regex, html_response, re.MULTILINE)
			#print url,        													#debug purpose
			#print reg_match													#debug purpose
			if reg_match:
				category = reg_match.group(1)
				# print "[*] Found! " + url + " = " + category   								#debug purpose
 				urlscategorized[url] = category
				return 1
			else:   #couldn't match, assuming proxy issue
				urllist.append(url)
				return 0
			#print "["  +  str(n) + "] proxy = " + proxy + "\t url = " + url  + "\tmessage = " + category 				#debug purpose
				
		except Exception, err:
				urllist.append(url)
				print "[I] exception["  +  str(n) + "] proxy = " + proxy + "\t url = " + url  + "\tmessage = " + str(err)
				return 0
				
				
""" main """
args = parser.parse_args()
urlList_pickledFile = args.urlList + ".pickled"
localURLCatdb_pickledFile = "localURLCatdb.pickled"

TIMEOUT = 10
USER_AGENT_FILE = 'user-agent_list.txt'

manager = multiprocessing.Manager()
urlList = manager.list()
urlsCategorized = manager.dict()
proxyQueue = Queue()
restoredDict = dict()

# load all urls from file into a list
try:
	with open( args.urlList, 'rb') as h:
		for line in h:
		    li=line.strip()
		    if not li.startswith("#"):
		    	urlList.append(li)
except:
	print "[I] Error opening/reading " + str(args.urlList) + ". Exiting..."
	exit()

# if urllist is empty, quits
if not urlList:
	print "[*] " + str(args.urlList) + " is empty. Exiting.."
	exit()

# load all proxies from file into a queue
try:
	with open( args.proxyList, "rb") as g:
		for line in g:
		    li=line.strip()
		    if not li.startswith("#"):
		    	proxyQueue.put(li)
except:
	print "[I] Error opening/reading " + str(args.proxyList) + ". Exiting..."
	exit()

# if the queue is empty, quits
if proxyQueue.empty():
	print "[I] " + str(args.proxyList) + " is empty. Exiting.."
	exit()

# load all known urls/categories 
try:
	f=open(localURLCatdb_pickledFile, 'rb')
	while 1:
		try:
			temp_dict= pickle.load(f)[0]
			restoredDict.update(temp_dict)
		except EOFError:
			break
		except Exception, err:
			print "[I] General Except: " + str(err)
			break
	f.close()
	categorizedURLsfromDB = manager.dict(restoredDict)
	
except:
	print "[I] Unable to load " + urlList_pickledFile + " (okay for a first run)"
	categorizedURLsfromDB = manager.dict()   #must be 

# backing up the original file (urllist)
try:
	if not os.path.isfile(args.urlList + '.bkp'):
		print "[*] Backing up " + str(args.urlList) + " ..."
		shutil.copyfile(args.urlList, args.urlList + '.bkp')
		print "[*] Done backing " + str(args.urlList) + " up..."
	else:
		print "[*] Backup file found for " + str(args.urlList) + ". Skipping backup..."
except:
	print "[I] Failed to backup " + str(args.urlList) + " (write access?)"
	exit()

# the main process
pool = multiprocessing.Pool(multiprocessing.cpu_count()*10)
while not proxyQueue.empty():
	if urlList:
		proxy_candidate = proxyQueue.get()
		for n in range(0,10):
			pool.apply_async(fetchCategory, args=(proxy_candidate, urlList, urlsCategorized, categorizedURLsfromDB,))
pool.close()
pool.join()	

backupDict = dict(urlsCategorized)
if checkFileExistence(urlList_pickledFile):
	pickleObject(backupDict, urlList_pickledFile)

backupDict.update(dict(categorizedURLsfromDB))  # could also iterate urlsCategorized and add the keys:values :|
if checkFileExistence(localURLCatdb_pickledFile):
	pickleObject(backupDict, localURLCatdb_pickledFile)

# writes the remaining urls that were not processed
# this effectively overwrites the original file
try:
		with open(args.urlList, 'w') as f:
			for s in urlList:
				f.write(s + "\n")
		print "[*] Successfully updated " + str(args.urlList)
except:
		print "[I] Error while updating " + str(args.urlList)

manager.shutdown()
del manager
