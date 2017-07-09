#!/usr/bin/python
#Este es el cliente para hacer pruebas de conexion
#Alpha version
#
# 	PENDING
#
#	1. Send info to server
#   2. Protection
#   3. Improve bypass Apple
#
#	PASOS
#
#	1. Apagar interface
#   2. Capturar con tcpdump, mitmproxy y mas
#
#   BUGS
#   1. Wireless with space
#   2. Timeout -_-
#   
################################################################################################
#MODULOS
#
import urllib2
import socket
import geocoder
import subprocess
import requests
import json
import sys
import argparse
import os

from wireless import Wireless
import subprocess
from selenium import webdriver
import time
import netifaces
import random

################################################################################################
#ARGPARSER
#-m requerido para decidir si cambiar mac address o no
#
parser = argparse.ArgumentParser(description='Free and Public Hotspot information gather!')
parser.add_argument('-m',help="Enable or Disable MAC Change",type=int,choices=[0,1],metavar='--mac', required=True, default=0,dest='mac')
#parser.add-argument('-c',help=)
args = vars(parser.parse_args())
argsMAC= args['mac']

################################################################################################
#CONFIG VAR
#
#host = "http://localhost:3000/"
#host = "https://ptkrm.me/wifi"

#CONSTANTES
#   PRODUCTION = False
#   DEBUG = True
DEBUG = True

ProxyAddress = 'localhost:8080'
NetworkInterface = 'en0'
#MAC = 'ac:bc:32:7f:63:c1'
CWD = os.getcwd()
wifi = Wireless(NetworkInterface)
CrawlNum = 10

#DEBUG OPTIONS
if DEBUG == False:
    evidenceDir = '/Evidence'
else:
    evidenceDir = '/Delete'

#VARIABLES
ip = ''
latlng = ''
networkInfo = {}
hotspotInfo = {}
dnsInfo = {}
addInfo = {}
captureTestInfo = {}

#LOAD ALEXA TOP WEBSITE
#Cargando ALEXA TOP Canada
with open('alexa/AlexaTopCA.txt') as f:
    alexaTop = f.readlines()

for i in range(0, len(alexaTop)):
    alexaTop[i] = alexaTop[i][0:-1]

################################################################################################
#FUNCTIONS
#
#SCAN SSID LOOKING FOR NONE SECURITY
#
def scanNone(output):
    pivot1 = []
    pivot2 = []

    for line in output.split('\n'):
        if 'NONE' in line:
            pivot1.append(line.strip())

    for x in pivot1:
        #print x
        d = x.split(" ")
        pivot2.append(d[0])

    pivot2 = list(set(pivot2))
    return pivot2

#RANDOM MAC GENERATOR
#THANK YOU CENTOS OFFICIAL DOCUMENTATION
#https://www.centos.org/docs/5/html/5.2/Virtualization/sect-Virtualization-Tips_and_tricks-Generating_a_new_unique_MAC_address.html
#
def randomMAC():
    mac = [ 0x00, 0x16, 0x3e,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def macAddressChanger(NetworkInterface ,MAC):
    print('Root Password is required for change MAC Address ')
    macChange = subprocess.Popen(['sudo','-k' ,'ifconfig', NetworkInterface, 'ether', MAC])
    macChange.wait()

def runTPCDump(NetworkInterface, Directory):
    process = subprocess.Popen(["tcpdump",'-i', NetworkInterface, '-s', '0', '-w',Directory+'/dump.pcap'])
    #time.sleep(5)
    return process

def runMITMProxy(NetworkInterface, Directory):
    process = subprocess.Popen(["mitmdump", '-w', Directory+'/mitmcapture', '-q'])
    time.sleep(3)
    return process

def theTerminator(p1, p2, driver):
    time.sleep(30)
    p1.terminate()
    p2.terminate()
    driver.close()
    wifi.power(False)
    exit()

def captureTest(driver, directory, websites, max):
    global captureTestInfo
    driver.set_page_load_timeout(30)
    for i in range(0, max):
        url = 'http://'+websites[i].lower()
        try:
            driver.get(url)
        except Exception as e:
            captureTestInfo[url] = 'Timeout: ' + e
        else:
            driver.save_screenshot(directory+'/'+websites[i].lower()+'.png')
            f = open(directory+'/'+websites[i].lower()+'.html', 'w')
            f.write(driver.page_source.encode('utf-8'))
            f.close()
            captureTestInfo[url+'-URL'] = driver.current_url
            captureTestInfo[url+'-Cookie'] = driver.get_cookies()
            time.sleep(5)
            print("Done: {}").format(websites[i])

################################################################################################
#VERIFY
#
if not (os.path.isdir(CWD+evidenceDir)):
    os.makedirs(CWD+evidenceDir)

evidenceDir = CWD+evidenceDir

################################################################################################
#START!
#
print('\n')
print('Public Hostpot Gathering - alpha version')
print('\n')

#SAVING MAC ADDRESS
if argsMAC == 1:
    print('''MAC Address Spoofing is ON: this is just required when you want to collect evidence again 
    for an previously associated hotspot, original MAC address is saved and restore at the end
    ''')
    MAC = netifaces.ifaddresses(NetworkInterface)[netifaces.AF_LINK][0]['addr']
    spoofMAC = randomMAC()
    print('MAC Address: {}').format(MAC)
    print('Fake MAC Address: {}').format(spoofMAC)
    print('\n')

    if wifi.power() == False:
        print 'Wireless Adapter is Off, turning ON'
        wifi.power(True)
        macAddressChanger(NetworkInterface, spoofMAC)
    else:
        macAddressChanger(NetworkInterface, spoofMAC)

print('\n')
print("Restarting Wireless Adapter")
#RESTART WIRELESS ADAPTER FOR MACCHANGER
if wifi.current() == None:
    wifi.power(False)
else:
    wifi.power(False)
wifi.power(True) 
print("Wireless Adapter is ON!")

#WIRELESS SCAN
print('\n')
print("Scanning for Open Wireless Networks")
wifiScan = subprocess.Popen(['airport', '-s'], stdout=subprocess.PIPE)
(output, err) = wifiScan.communicate()
wifiScanResult = scanNone(output)

#MENU SELECTOR PARA ESCOGER EL WIFI PUBLICO
#EVALUAR STATUS SI CONECTA A LA RED O NO!
#print wifiScanResult
connection = False
i = 0
print "Open Wireless Network"
for x in wifiScanResult:
    print("int value: {} - SSID: {}").format(i, x)
    i += 1

verify = False
p = 0
while verify == False:
    p = raw_input("Select a Wireless Network (Just inset the int value): ")
    if(not p or p.isalpha() or " " in p):
        print "Enter an Integer Value"
    else:
        p = int(p)
        if p < len(wifiScanResult):
            verify = True
        else:
            print "Not valid Integer Value"
verify = ''

#CREATE SSID-CURRENTTIME EVIDENCE DIRECTORY
timeStr = time.strftime("%d%m%Y_%H%M")
evidenceDir = evidenceDir+'/'+wifiScanResult[p]+'-'+timeStr
searchTestDir = evidenceDir + '/SearchTest'
captureTestDir = evidenceDir + '/CaptureTest'
addDir = evidenceDir+'/Additional'

if not (os.path.isdir(evidenceDir)):
    os.makedirs(evidenceDir)
    os.makedirs(searchTestDir)
    os.makedirs(captureTestDir)
    os.makedirs(addDir)

print("Current Working Dir: {}").format(evidenceDir)

#STARTING WEB PROXY AND TCPDUMP
tcpdump = runTPCDump(NetworkInterface, evidenceDir)
proxy = runMITMProxy(NetworkInterface, evidenceDir)

#EVITAR OUT OF RANGE Y VERIFICAR MEJOR
try:
    connection = wifi.connect(wifiScanResult[p], '')
except Exception, e:
    print e

#VERIFY IP ADDRESS
#proc = subprocess.Popen(['sudo','ifconfig','en0','down'])
#proc.wait()
#print 'BOOM'
time.sleep(2)
verify = False
i = 0
while verify == False:
    ip = netifaces.ifaddresses(NetworkInterface)
    try:
        ip[netifaces.AF_INET]
        verify = True
    except Exception, e:
        if i > 3:
            print "30 Seconds Timeout"
            theTerminator(tcpdump, proxy)
        else:
            print "Asignando IP"
            verify = False
            time.sleep(10)
            connection = wifi.connect(wifiScanResult[p], '')
            i += 1

################################################################################################
#
#BROWSER AUTOMATITATION
time.sleep(2)
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument('--proxy-server=http://'+ProxyAddress)
chrome_options.add_argument('user-data-dir='+evidenceDir+'/BrowserProfile')
chrome = webdriver.Chrome(chrome_options=chrome_options)
time.sleep(5)
chrome.get('http://abc.com')
hotspotInfo['cookies'] = chrome.get_cookies()
hotspotInfo['url'] = chrome.current_url
chrome.save_screenshot(evidenceDir+'/hotspot.png')
f = open(evidenceDir+'/hotspot.html', 'w')
f.write(chrome.page_source.encode('utf-8'))
f.close()

print("PLEASE: Using recently open windows, join into the free public hotspot")
#DETERMINE METHOD TO HOTSPOT
#FOR NOW JUST NEED Y OR N
#Thank you stackoverflow - http://stackoverflow.com/questions/3041986/apt-command-line-interface-like-yes-no-input
yes = set(['yes','y', 'ye'])
gathering = set(['g','s','1',''])
gnumber=0
no = set(['no','n'])

#HOTSPOT MODE ALLOW ME TO GATHER INFORMATION ABOUT HOTSPOT WEBSITE
verify = False
while verify == False:
    confirm = raw_input("HOTSPOT Login information, Using browser take evidence a press G to save it, Write Y after you loging: ").lower()
    if confirm in yes:
        verify = True
    elif confirm in gathering:
        hotspotInfo['cookies-'+str(gnumber)] = chrome.get_cookies()
        hotspotInfo['url-'+str(gnumber)] = chrome.current_url
        chrome.save_screenshot(evidenceDir+'/hotspot-'+str(gnumber)+'.png')
        f = open(evidenceDir+'/hotspot-'+str(gnumber)+'.html', 'w')
        f.write(chrome.page_source.encode('utf-8'))
        f.close()
        gnumber += 1
    elif confirm in no:
        print("Shutdown Muahahaha!!")
        theTerminator(tcpdump, proxy, chrome)
    else:
        print("Please select y or n")

#while verify == False:
#    try:
#        urllib2.open('http://ptkrm.me', timeout=1)

#NETWORK INFORMATION
#GEOCODER
g = geocoder.ipinfo('me')
ip = g.ip
networkInfo['ip'] = ip
latlng = g.latlng
networkInfo['latlng'] = latlng
networkInfo['interface'] = netifaces.ifaddresses(NetworkInterface)

#COPY RESOLV.CONF IN OSX & LINUX DNS CONFIG IS STORE HERE
i = 0
with open("/etc/resolv.conf","r") as readFile:
    for line in readFile.readlines():
        if line.startswith("nameserver"):
            networkInfo['nameserver'+str(i)] = line.split(" ")[1].strip()
            i += 1

print('IP: {}').format(ip)
print('Latitude and Longitud: {}').format(latlng)
print(hotspotInfo)
print(networkInfo)

#WRITING EVIDENCE
with open(evidenceDir+'/hostpost.json', 'w') as file:
    json.dump(hotspotInfo, file)

with open(evidenceDir+'/network.json', 'w') as file:
    json.dump(networkInfo, file)

#DNSTEST USING TOP ALEXA
i = 0
for i in range(0, CrawlNum):
    try:
        dnsInfo[alexaTop[i].lower()] = socket.gethostbyname_ex(alexaTop[i].lower())
    except Exception as e:
        print("Error: {}").format(e)

#NXDOMAIN AGAINST FAUX DOMAIN
faux = ['dom.falso', 'abcxxxxxdsa.com', 'queloooooo.ca', 'casdadascas.com']
wrong = 0
execution = 0
for domain in faux:
    try:
        dnsInfo['NXDOMAIN:'+domain] = socket.gethostbyname_ex(domain)
        wrong += 1
        chrome.get('http://'+domain)
        dnsInfo['NXDOMAIN-Cookies:'+domain] = chrome.get_cookies()
        dnsInfo['NXDOMAIN-URL'+domain] = chrome.current_url
        chrome.save_screenshot(evidenceDir+'/NXDOMAIN-' + domain + '.png')
        f = open(evidenceDir+'/NXDOMAIN-'+ domain + '.html', 'w')
        f.write(chrome.page_source.encode('utf-8'))
        f.close()
        execution += 1
    except Exception as e:
        execution += 1
        print("{}/4").format(str(execution))
    
if wrong > 0:
    print 'NXDOMAIN REDIRECTION DETECTED Review Evidence'

#WRITING EVIDENCE
with open(evidenceDir+'/dns.json', 'w') as file:
    json.dump(dnsInfo, file)

#SELENIUM TEST
captureTest(chrome, captureTestDir, alexaTop, CrawlNum)

#WRITING EVIDENCE
with open(evidenceDir+'/captureTest.json', 'w') as file:
    json.dump(captureTestInfo, file)

#FREE MODE TO COLLECT ADDITIONAL EVIDENCE, OR MANUAL MODE
exitO = set(['e','ex', 'exit'])
gathering = set(['g','s','1', ''])
anum=0

verify = False
while verify == False:
    confirm = raw_input("Gather Additional Information (/Additiona) with G or Finish Run with E: ").lower()
    if confirm in exitO:
        verify = True
    elif confirm in gathering:
        addInfo['cookies-'+str(anum)] = chrome.get_cookies()
        addInfo['url-'+str(anum)] = chrome.current_url
        chrome.save_screenshot(addDir+'/add-'+str(anum)+'.png')
        f = open(addDir+'/add-'+str(anum)+'.html', 'w')
        f.write(chrome.page_source.encode('utf-8'))
        f.close()
        anum += 1
    else:
        print("Please select G or E")

with open(evidenceDir+'/additional.json', 'w') as file:
    json.dump(addInfo, file)

#ESTO SE VA A DESCONTROLAAAAR
print("END RUN - find evidence into {}").format(evidenceDir)
time.sleep(10)
theTerminator(tcpdump, proxy, chrome)

