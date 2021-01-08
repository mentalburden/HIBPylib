import time
import json
import boto3
import urllib3

s3_client = boto3.client('s3')
webber = urllib3.PoolManager()

apiurl = 'https://haveibeenpwned.com/api/v3'
apikey = "noway" 
reportout = ''
lnamefile = "lnames.txt"
fnamefile = "fnames.txt"

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
                        return ["nope", "nope", "nope", "nope"]



def checkdomain(query, apikey):
        apiendpoint = apiurl + '/breaches/?domain=' + query
        headerboi =  {'user-agent': 'MBdevops v1 hibpscript','hibp-api-key': str(apikey)}
        req = webber.request('GET', apiendpoint, headers=headerboi)
        reqjson = json.loads(req.data.decode('utf-8'))
        print(reqjson)
        try:
                jason = jsontoarray(reqjson)
                return jason
        except:
                return ["nope", "nope", "nope", "nope"]

def checkuser(query, apikey):
        cleanquery = query.replace('@',"%40") #gets around using urllib for encoding
        apiendpoint = apiurl + '/breachedaccount/' + cleanquery
        headerboi =  {'user-agent': 'MBdevops v1 hibpscript','hibp-api-key': str(apikey)}
        req = requests.get(apiendpoint, headers=headerboi)
        print(req.content)

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

def writetos3(domain, outarray):
        bucket_name = "hibp-scraper-"
        try:
               chonk = ','.join(outarray)
        except:
                chonk = "none-found, , , "
        encoded_string = chonk.encode("utf-8")
        #lambda_path = "/tmp/" + domain + "-record.csv"
        s3_path = "testchonkers/" + domain + "-record.csv"
        s3 = boto3.resource("s3")
        s3.Bucket(bucket_name).put_object(Key=s3_path, Body=encoded_string)
        
def readfroms3(filetoread):
        bucket_name = "hibp-scraper-"
        s3 = boto3.resource("s3")
        thisfile = s3.Object(bucket_name, filetoread)
        rawfile = thisfile.get()['Body'].read().decode('utf-8')
        return rawfile.splitlines()

###main starts here sorta
def lambda_handler(event, context):
    targets = readfroms3("targets.txt")
    for target in targets:
        print(target)
        chonklet = checkdomain(target, apikey)
        print(chonklet)
        writetos3(str(target), chonklet)
