import time
import json
import boto3
import urllib3

s3_client = boto3.client('s3')
webber = urllib3.PoolManager()

apiurl = 'https://haveibeenpwned.com/api/v3'
apikey = "noway" #MB/ owned api key, good till 6FEB20
bucket_name = "hibp-scraper-emilyt"
s3_fullpath = "testchonkers/"

#stuff for later starts here
reportout = ''
lnamefile = "lnames.txt"
fnamefile = "fnames.txt"

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
        alphabet = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
        for lname in lnames:
                for letter in alphabet:
                        if (len(letter) >= 1): # removes empty \n index
                                thisarray.append(letter + lname.replace("\n", '') + domain)
        return thisarray

#hibp to s3/csv starts here

def jsontoarray(thisjason):
        #grabs all the important stuff and creates a str array
        #shrink this to one liners later on and fix the nonetype error
        try:
                for chonk in thisjason:
                        name = str(chonk['Name'])
                        mdate = str(chonk['ModifiedDate'])
                        longdesc = str(chonk['Description'])
                        pwncount = str(chonk['PwnCount'])
                        return [name, mdate, longdesc, pwncount]
        except:
                        return

def checkdomain(query, apikey):
        apiendpoint = apiurl + '/breaches/?domain=' + query
        headerboi =  {'user-agent': 'MBdevops v1 hibpscript','hibp-api-key': str(apikey)}
        req = webber.request('GET', apiendpoint, headers=headerboi)
        reqjson = json.loads(req.data.decode('utf-8'))
        try:
                jason = jsontoarray(reqjson)
                return jason
        except:
                return [str(query), "no-breaches-found", "no-breaches-found", "no-breaches-found"]

def checkuserisbrokenrightnow(query, apikey): #needs to get moved to urllib3 instead, requests is jacked up for boto/lambda
        cleanquery = query.replace('@',"%40") #gets around using urllib for encoding
        apiendpoint = apiurl + '/breachedaccount/' + cleanquery
        headerboi =  {'user-agent': 'MBdevops v1 hibpscript','hibp-api-key': str(apikey)}
        req = requests.get(apiendpoint, headers=headerboi)
        print(req.content)

def readfroms3(filetoread):
        s3 = boto3.resource("s3")
        thisfile = s3.Object(bucket_name, filetoread)
        rawfile = thisfile.get()['Body'].read().decode('utf-8')
        print(rawfile)
        return rawfile
        
def checkfileexists(domain):
        s3_path = s3_fullpath + domain + "-record.csv" #globalize these later you dumdum
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
                chonk = currentcontent + "\n"
                for i in newarray:
                        chonk += str(i) + ", "
                chonk += "\n"
        s3_path = s3_fullpath + domain + "-record.csv"
        s3 = boto3.resource("s3")
        s3.Bucket(bucket_name).put_object(Key=s3_path, Body=str(chonk))
        
def updates3file(domain, outarray):
        filestate = checkfileexists(domain)
        if filestate is not None:
                currentcontent = readfroms3(filestate) #Cast old file read as string for easier \n handling
                writetos3(domain, outarray, False, currentcontent)
        elif filestate is None:
                writetos3(domain, outarray, True, "NOPE")

###main starts here sorta
def lambda_handler(event, context):
    targets = readfroms3("targets.txt").splitlines() #array'ify the target list
    for target in targets:
        print(target)
        chonklet = checkdomain(target, apikey)
        if chonklet is not None:
                updates3file(str(target), chonklet)
        else:
                updates3file(str(target), [str(target), "No-Breach-Found", "Datestamp-here", "somethingelse-here"])
