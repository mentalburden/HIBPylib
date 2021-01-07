#!/usr/bin/python3

#flow:
#target.txt file is fed to script, each line a domain, \n delim'ed
#each line gets checked for a breach
#if breach found, the newest and oldest breaches/events are pulled
#and if breach found, pull all usersnames in dump if able (should be able to recurse this, maybe)
#everything is shoved into a clean array
#Array to csv, then do latex report gen and nosql posts

#done: api auth, check for plaintext domain, check for full plaintext addy

#needs: check for single/last name and username word list combo addresses for known good breaches, array to csv crap, and lambda compat POST/PUT input and response to API'ify script (WIP)

import json
import requests

apiurl = 'https://haveibeenpwned.com/api/v3'
reportout = ''

def jsonchonker(thisjason):
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
        jason = jsonchonker(req.json())
        if jason is not None:
                #start drilldown func get here for known good breach
                print(jason)
        else:
                print("Nothing found for " + query)

def checkaccount(query, apikey):
        cleanquery = query.replace('@',"%40") #gets around using urllib for encoding
        apiendpoint = apiurl + '/breachedaccount/' + cleanquery
        headerboi =  {'user-agent': 'MBdevops v1 hibpscript','hibp-api-key': str(apikey)}
        req = requests.get(apiendpoint, headers=headerboi)
        print(req.content)


###MAIN STARTS HERE
#get apikey, make it global later on
with open('apikey.txt', 'r') as apifile:
        apikey = apifile.read().replace('\n','')
#get target list, make it argparse or lambda'able later on
with open('targets.txt', 'r') as targetfile:
        targetlist = targetfile.read().splitlines() # \n removal hax
        for i in targetlist:
                checkdomain(str(i), apikey)
