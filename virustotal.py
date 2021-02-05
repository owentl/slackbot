import argparse
import hashlib
import re
import requests
import json
import socket
import sys

## Credit to https://github.com/ecapuano/slackbot for this code!

debug = "yes" # set to 'yes' to print messages to console

def virustotal_search(vtarg):
    api_key = ''
    url_base = 'https://www.virustotal.com/vtapi/v2/'
    headers = {
      "X-Apikey": api_key
    }
    regex = ("((http|https)://)(www.)?" + "[a-zA-Z0-9@:%._\\+~#?&//=]" +
             "{2,256}\\.[a-z]" + "{2,6}\\b([-a-zA-Z0-9@:%" + "._\\+~#?&//=]*)")
    p = re.compile(regex)
    if (re.search(p, vtarg)) or ("www" in vtarg) or (".com" in vtarg):
        if debug == "yes":
            print("URL Detected")
        param = {'resource':vtarg,'apikey':api_key}
        url = url_base + "url/report"
        result = requests.get(url,params=param)
        jdata = result.json()
        print(jdata)
        message = urlparse(jdata)
    elif re.findall(r"([a-fA-F\d]{32})", vtarg):
        if debug == "yes":
            print("MD5 detected")
        # param = {'resource':md5,'apikey':api_key}
        param = {'resource':vtarg,'apikey':api_key}
        url = url_base + "file/report"
        result = requests.get(url,params=param)
        jdata = result.json()
        # print(result.text)
        message = parse(jdata)
    else:
        if debug == "yes":
            print("Not URL or MD5")
        message = "You did not provide a valid URL or MD5 hash.\nPlease try again in the format `/virustotal http://malware.ru` or `/virustotal 99017f6eebbac24f351415dd410d522d`"
        status = "fail"
    print(message)
    return message


################### Not in use yet
def checkMD5(checkval):
  if re.match(r"([a-fA-F\d]{32})", checkval) == None:
    md5 = md5sum(checkval)
    return md5.upper()
  else:
    return checkval.upper()

def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest()
####################

def parse(jdata):
  message = ""
  if jdata['response_code'] == 0:
    message = "That Hash Not Found in VT"
  else:
      md5 = str(jdata['md5'])
      sha1 = str(jdata['sha1'])
      if jdata['md5']:
          message = "Results for File: \t" + str(jdata['md5']) + "\n"
      elif jdata['sha1']:
          message = "Results for File: \t" + str(jdata['sha1']) + "\n"
      message += "Detected Malicious by: \t" + str(jdata['positives']) + "/" + str(jdata['total']) + "\n"

      for key in jdata['scans']:
          print(key)
          message += "*" + key + " ("+ str(jdata['scans'][key]['version'])+"): *\t" + str(jdata['scans'][key]['detected']) + "\n"

      message += 'Scanned on: \t' + jdata['scan_date'] + "\n"
      message += jdata['permalink'] + "\n"
      if debug == "yes":
          print(message)
  return message

def urlparse(jdata):
  message = ""
  if jdata['response_code'] == 0:
    message = "That Site Not Found in VirusTotal"
    if debug == "yes":
        print("Request not found in VT database.")
  else:
    positives = str(jdata['positives'])
    total = str(jdata['total'])
    url = jdata['url']
    message = "*Results for Site:* \t" + url + "\n"
    message += "*Determined Malicious by:* \t" + positives + "/" + total + "\n"

    for key in jdata['scans']:
      vtres = jdata.get('scans', {}).get(key).get('result')
      resultsout = ""
      if vtres == "clean site":
          resultsout = vtres + ' :thumbsup:'
      elif vtres == "unrated site":
          resultsout = vtres + ' :question:'
      elif vtres == "phishing site":
          resultsout = vtres + ' :fishing_pole_and_fish:'
      else:
            resultsout = vtres
      message += "*" + key + ": *\t" + resultsout + "\n"

    message += '*Scanned on:* \t' + jdata['scan_date'] + "\n"
    message += jdata['permalink'] + "\n"
    if debug == "yes":
      print(message)

  return message

#use these for local testing
# virustotal_search('http://malware.net')
# virustotal_search('f8475d4cc5857f61ea03dc0d35efa389fff79f34')
