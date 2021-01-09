####psudocode for HIBP script:
#lambda entrypoint 
####currently using a lambda cronjob/trigger/lambda test
####can turn this into an api style call later if needs to be fired from c2 box
#read target domain list (target.txt) from s3:
#	for each valid domain:
#		check for breaches
#		try
#			if breach exists:
#				create/append csv with breach details
#				check for userlist for domain
#				append valid breach name to worker array; for each in array:
#					if check true:
#						run check for every email (whitebox username check) 
#						#need an example dc/domain user dump to work with
#					if check false:
#						dynamically generate username combos from common wordlist (blackbox username check) 
#						#uses short kaggle tax/voter record names, need to build bigger/better lists
#			elif no breach exists:
#				create/append csv with "no breach found" message
#			job log out#
#		catch
#			job log out with error code

import time
import json
import boto3
import urllib3

s3_client = boto3.client('s3')
webber = urllib3.PoolManager()

apilimit = 0.3
apiurl = 'https://haveibeenpwned.com/api/v3'
apikey = "" #MB owned api key, good till 6FEB20-------------------------REDACT ME!
bucket_name = "hibp-scraper-" #-------------------------------------------------------------------------REDACT ME!
s3_fullpath = "examplechonkers/"
thistime = time.strftime("%Y-%m-%d %H:%M:%S") #use logging/syslog'er later on

#namegen junk starts here
reportout = ''
lnamefile = "lnames.txt"
fnamefile = "fnames.txt"
testnamefile = "tnames.txt"

def genfirstdotlast(fnames, lnames, domain):
        #tiffany.chonksmith@whatever.net
        thisarray = []
        for lname in lnames:
                for fname in fnames:
                        if (len(fname) > 2): # remove empty \n index
                                thisarray.append(fname.replace("\n", '') + "." + lname.replace("\n", "") + domain)
        return thisarray

def genletterdotlast(lnames, domain):
        #tchonksmith@whatever.net
        thisarray = []
        #alphabet = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'] #full run
        alphabet = ['a'] #debug
        for lname in lnames:
                for letter in alphabet:
                        if (len(letter) >= 1): # removes empty \n index
                                thisarray.append(letter + lname.replace("\n", '') + "@" + domain)
        return thisarray

#hibp to s3/csv starts here

def userjsontoarray(thisjason):
        #grabs all the important stuff and creates a str array
        #shrink this to one liners later on and fix the nonetype error
        #print(thisjason)
        userbreachdomains = []
        try:
                for chonk in thisjason:
                        name = str(chonk['Name'])
                        userbreachdomains.append(name)
                return userbreachdomains
        except:
                        return

def checkuser(query, apikey): 
        cleanquery = query.replace('@',"%40").lower() #switch back to urllib encode later
        apiendpoint = apiurl + '/breachedaccount/' + cleanquery
        headerboi =  {'Content-Type': 'application/json', 'user-agent': 'MBdevops hibpscript-checkuser V1','hibp-api-key': str(apikey)}
        req = webber.request('GET', apiendpoint, headers=headerboi)
        #print(str(req.data) + " " + cleanquery + "\n")
        try:
                reqjson = json.loads(req.data.decode('utf-8'))
                jason = userjsontoarray(reqjson)
                time.sleep(apilimit)
                return [query.lower(), "BREACHES FOUND", jason, thistime]
        except Exception as errboi:
                #time.sleep(apilimit)
                #return Nonetype later on, this is fine for now doesnt do anything tho
                #return [query.lower(), "no-breaches-found", "no-breaches-found", thistime]
                return None

def breachjsontoarray(thisjason):
        #grabs all the important stuff and creates a str array
        #shrink this to one liners later on and fix the nonetype error
        try:
                for chonk in thisjason:
                        name = "BREACH NAME: " + str(chonk['Name'])
                        mdate = "BREACH DATE: " + str(chonk['ModifiedDate'])
                        longdesc = "LONG DESC: {{{" + str(chonk['Description']) + "}}}"
                        pwncount = "BREACHED ACCOUNTS: " + str(chonk['PwnCount'])
                        #and script run timestamp
                        return [name, mdate, longdesc, pwncount, thistime]
        except:
                        return

def checkdomain(query, apikey):
        apiendpoint = apiurl + '/breaches/?domain=' + query
        headerboi =  {'user-agent': 'MBdevops hibpscript-checkbreach V1','hibp-api-key': str(apikey)}
        req = webber.request('GET', apiendpoint, headers=headerboi)
        reqjson = json.loads(req.data.decode('utf-8'))
        try:
                jason = breachjsontoarray(reqjson)
                time.sleep(apilimit)
                return jason #get them to scrap the csv crap and go json, but later
        except:
                #time.sleep(apilimit)
                #return Nonetype later on, this is fine for now doesnt do anything tho
                return [str(query), "no-breaches-found", "no-breaches-found", "no-breaches-found"] 

def readfroms3(filetoread):
        s3 = boto3.resource("s3")
        thisfile = s3.Object(bucket_name, filetoread)
        rawfile = thisfile.get()['Body'].read().decode('utf-8')
        #print(rawfile)
        return rawfile
        
def checkfileexists(domain):
        s3_path = s3_fullpath + domain + "-record.csv"
        try:
                obj = s3_client.head_object(Bucket=bucket_name, Key=s3_path)
                return s3_path
        except:
                return None

def writetos3(domain, newarray, isnew, currentcontent):
        chonk = ""
        if isnew is True:
                for i in newarray:
                        chonk += str(i) + ", "
                chonk += "\n"
        elif isnew is False:
                chonk = currentcontent
                for i in newarray:
                        chonk += str(i) + ", "
                chonk += "\n"
        s3_path = s3_fullpath + domain + "-record.csv"
        s3 = boto3.resource("s3")
        s3.Bucket(bucket_name).put_object(Key=s3_path, Body=str(chonk))
        
def updates3file(domain, outarray):
        filestate = checkfileexists(domain)
        if filestate is not None:
                currentcontent = readfroms3(filestate) 
                writetos3(domain, outarray, False, currentcontent) # stupid bool, change it later dumdum
        elif filestate is None:
                writetos3(domain, outarray, True, "NOAP") #fix placeholder with multivar func later

def targetlistrunner():
        validtargets = []
        targets = readfroms3("targets.txt").splitlines() #array'ify the target list
        for target in targets:
                print(target)
                chonklet = checkdomain(target, apikey)
                if chonklet is not None:
                        updates3file(str(target), chonklet)
                        validtargets.append(target)
                else:
                        updates3file(str(target), [str(target), "No-Breach-Found", "other info can be added...", thistime])
        return validtargets
        
def letterdotlastrunner(domain):
        breachedusers = []
        for user in genletterdotlast(readfroms3(fnamefile).splitlines(), domain):
                thisuser = checkuser(user, apikey)
                if thisuser is not None:
                        #FIX THIS CRAP BELOW: DUMB AF
                        #do a single write/append on breachedusers and rebuild the csv stringbanger for userbreach funcs
                        userfile = str(domain) + "-userbreaches"
                        updates3file(userfile, thisuser) 
                        breachedusers.append(thisuser)
        return breachedusers #fire this array into ES as syslog form'ed jsons for hive alerts

###main starts here sorta
def lambda_handler(event, context):
        targets = targetlistrunner() #shrink this func chain, ooo000 spaghet
        print(targets)
        for target in targets:
                print("running user targets")
                for user in letterdotlastrunner(target):
                        print(user)
