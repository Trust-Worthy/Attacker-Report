#!/usr/bin/python3.6

from subprocess import PIPE, run, call
import os
import regex as re
from geoip import geolite2

'''Jonathan Bateman Script 4. November 7th 2023. Mikly Way Galaxy, Planet Earch. Star Log 454'''

'''Clear the Terminal'''
call('clear')

'''Locate the syslog.log file'''
filename = "syslog.log"
search_path = "/"
result = []

for root, dir, files in os.walk(search_path):
    if filename in files:
        result.append(os.path.join(root,filename))

syslog_path = ''.join(result)

'''Search the syslog.log file. Find where failed login attempt is made
    1. Capture ip address of login attempt
    2. Count number of failed login attempts by ip address
    3. Capture the country of origin of ip address'''

failed_logins = []
ip_addresses = []

with open(syslog_path,"r") as file:
    while file.readline() != "":
        line = file.readline()
        if re.search("Failed",line) != None:
            failed_logins.append(line)

for record in failed_logins:
    #if re.search("\d.{3}[.]",record):
    ip_addresses.extend(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",record)) # regex to get ip address from file


ip_dict = dict.fromkeys(ip_addresses,0) # creating dictionary: ip address is key and value is num login attemps

'''Count number of login attempts from each ip address'''
for key in ip_dict:
    for ip in ip_addresses:
        if key == ip:
            ip_dict[key] += 1
        else:
            continue

'''create dictionary for all the countries of ip origin'''
country_origin = dict.fromkeys(ip_dict," ")

for key in country_origin:
    match = geolite2.lookup(key)
    if match == None:
        country_origin[key] = "Not Found" 
    else:
        country_origin[key] = match.country

result  = run("date",stdout=PIPE,stderr=PIPE,universal_newlines=True)
date = result.stdout


'''Creating the format string'''

print("Attacker Report --",date )

print("COUNT\tIP ADDRESS\tCOUNTRY")

temp = list(ip_dict.values())
temp = sorted(temp) # sort number of login attemps from least to greatest
temp.pop(0)
for val in temp:
    for key, value in ip_dict.items():
        if val == value:
            print("{}\t{}\t{}".format(val,key,country_origin[key]))

