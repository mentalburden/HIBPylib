import time
import json
from botocore.vendored import requests #hacky fix, need to find the "lambda" way to do requests

apiurl = 'https://haveibeenpwned.com/api/v3'
apikey = "hahayeahrightimnotthattiredyet"
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
        req = requests.get(apiendpoint, headers=headerboi)
        jason = jsontoarray(req.json())
        if jason is not None:
                #start drilldown func here for good hit
                print(jason)
        else:
                print("Nothing found for " + query)

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

###main starts here sorta
def lambda_handler(event, context):
    chonker = event[("chonker")]
    chonklet = checkdomain(chonker, apikey)
    return 
    {
        "message" : chonklet
    }
