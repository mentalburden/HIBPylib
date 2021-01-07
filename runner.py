#!/usr/bin/python3

#done: check for plaintext domain, check for full plaintext addy, generate first.last and flast users for domain and check all

#needs: lambda compat POST/PUT input and response to API'ify script (WIP), make jsontoarray -> csv/lambda response happen

import time
import json
import requests

apiurl = 'https://haveibeenpwned.com/api/v3'
apikey = "lolno"
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


###MAIN STARTS HERE
#namegen works and returns a username array for given domain
#print(genfirstdotlast(open(fnamefile, 'r').readlines(), open(lnamefile, 'r').readlines(), "@chonkerdomain.net"))

#namegen -> checkusername call with rate limiter example
#for user in (genletterdotlast(open(lnamefile, 'r').readlines(), "@adobe.net")):
#       checkuser(user, apikey)
#       time.sleep(1.5);

#get target list, make it argparse or lambda'able later on
#with open('targets.txt', 'r') as targetfile:
#       targetlist = targetfile.read().splitlines() # \n removal hax
#       for i in targetlist:
#               checkdomain(str(i), apikey)
