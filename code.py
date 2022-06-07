from shutil import which
from shodan import Shodan
from colorama import Fore, Back, Style
from os import path
from builtwith import builtwith
from modules.favicon import *
import socket
import subprocess
import sys
import socket
import argparse
import requests


requests.packages.urllib3.disable_warnings()


def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

group.add_argument('-sv', '--save', action='store',
                   help="save output to file",
                   metavar="filename.txt")

parser.add_argument('-s',
                    type=str, help='scan for subdomains',
                    metavar='domain.com')

parser.add_argument('-r', '--redirects',
                    type=str, help='links getting redirected',
                    metavar='domains.txt')

parser.add_argument('-b', '--brokenlinks',
                    type=str, help='search for broken links',
                    metavar='domains.txt')

parser.add_argument('-w', '--waybackurls',
                    type=str, help='scan for waybackurls',
                    metavar='https://domain.com')

parser.add_argument('-wc', '--webcrawler',
                    type=str, help='scan for urls and js files',
                    metavar='https://domain.com')

parser.add_argument('-ri', '--reverseip',
                    type=str, help='reverse ip lookup',
                    metavar='IP')


parser.add_argument('-co', '--corsmisconfig',
                    type=str, help='get favicon hashes',
                    metavar='https://domain.com')

parser.add_argument('-hh', '--hostheaderinjection',
                    type=str, help='host header injection',
                    metavar='domains.txt')

args = parser.parse_args()



if args.s:
    if args.save:
        print(Fore.CYAN + "Saving output to {}...".format(args.save))
        cmd = f"subfinder -d {args.s}"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, err = p.communicate()
        out = out.decode()  
        with open(f"{args.save}", "w") as subfinder:
            subfinder.writelines(out)
        if path.exists(f"{args.save}"):
            print(Fore.GREEN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.RED + "ERROR!")
            sys.exit(1)
        cmd = f"./scripts/spotter.sh {args.s} | uniq | sort"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        spotterout, err = p.communicate()
        spotterout = spotterout.decode()
        with open(f"{args.save}", "a") as spotter:
            spotter.writelines(spotterout)
        cmd = f"./scripts/certsh.sh {args.s} | uniq | sort"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        certshout, err = p.communicate()
        certshout = certshout.decode()
    else:
        commands(f"subfinder -d {args.s}")
        commands(f"./scripts/spotter.sh {args.s} | uniq | sort")
        commands(f"./scripts/certsh.sh {args.s} | uniq | sort") 

if args.reverseip:
    domain = socket.gethostbyaddr(args.reverseip)
    print(f"{Fore.CYAN}Domain: {Fore.GREEN} {domain[0]}")


if args.webcrawler:
    if args.save:
        print(Fore.CYAN + f"Saving output to {args.save}")
        commands(f"echo {args.webcrawler} | hakrawler >> {args.save}")
    else:
        commands(f"echo {args.webcrawler} | hakrawler")




if args.corsmisconfig:
    print(f"\t\t\t{Fore.CYAN}CORS {Fore.MAGENTA}Misconfiguration {Fore.GREEN}Module\n\n")
    with open(f"{args.corsmisconfig}") as f:
        domains = (x.strip() for x in f.readlines())
        try:
            for domainlist in domains:
                for pos, web in enumerate(domainlist):
                    if pos == 0:
                        original_payload = []
                        payload = []
                        remove_com = domainlist.replace(".com", "")
                        payload.append(f"{remove_com}evil.com")
                        payload.append("evil.com")
                        header = {'Origin': f"{payload}"}
                    else:
                        pass
                [original_payload.append(i) for i in payload if i not in original_payload]
                original_payload2 = ", ".join(original_payload)
                session = requests.Session()
                session.max_redirects = 10
                resp = session.get(f"{domainlist}", verify=False, headers=header)
                for value, key in resp.headers.items():
                    if value == "Access-Control-Allow-Origin":
                        AllowOrigin = key
                        if AllowOrigin == f"{payload}":
                            print(f"{Fore.YELLOW}VULNERABLE: {Fore.GREEN}{domainlist} {Fore.CYAN}PAYLOADS: {Fore.MAGENTA}{original_payload2}")
                print(f"{Fore.CYAN}NOT VULNERABLE: {Fore.GREEN} {domainlist} {Fore.CYAN}PAYLOADS: {Fore.MAGENTA}{original_payload2}")
        except requests.exceptions.TooManyRedirects:
            pass
        except requests.exceptions.ConnectionError:
            pass

if args.hostheaderinjection:
    print(f"{Fore.MAGENTA}\t\t Host Header Injection \n")
    redirect = ["301", "302", "303", "307", "308"]
    with open(f"{args.hostheaderinjection}") as f:
        domains = [x.strip() for x in f.readlines()]
        payload = b"evil.com"
        vuln_domain = []
        duplicates_none = []     
        try:
            for domainlist in domains:
                session = requests.Session()
                header = {"X-Forwarded-Host": "evil.com"}
                header2 = {"Host": "evil.com"}
                resp = session.get(f"{domainlist}", verify=False, headers=header)
                resp2 = session.get(f"{domainlist}", verify=False, headers=header2)
                resp_content = resp.content
                resp_status = resp.status_code
                resp2_content = resp2.content
                for value, key in resp.headers.items():
                    if value == "Location" and key == payload and resp.status_code in redirect:
                        vuln_domain.append(domainlist)
                    if payload in resp_content or payload in resp2_content or key == payload:
                        vuln_domain.append(domainlist)
                if vuln_domain:
                    print(f"{Fore.YELLOW} Host Header Injection Detected {Fore.MAGENTA}- {Fore.GREEN} {vuln_domain}")
                [duplicates_none.append(x) for x in vuln_domain if x not in duplicates_none]
                print(f"{Fore.CYAN} No Detection {Fore.MAGENTA}- {Fore.GREEN} {(domainlist)}{Fore.BLUE} ({resp_status})")
        except requests.exceptions.TooManyRedirects:
            pass


if args.waybackurls:
    if args.save:
        print(Fore.CYAN + f"Saving output to {args.save}")
        commands(f"waybackurls {args.waybackurls} | anew >> {args.save}")
        print(Fore.GREEN + "DONE!")
    else:
        commands(f"waybackurls {args.waybackurls}")



if args.redirects:
    if args.save:
        print(Fore.CYAN + "Saving output to {}}..".format(args.save))
        commands(f"cat {args.redirects} | httpx -silent -location -mc 301,302 | anew >> redirects.txt")
        if path.exists(f"{args.save}"):
            print(Fore.GREEN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.RED + "ERROR!")
    else:
        commands(f"cat {args.redirects} | httpx -silent -location -mc 301,302")   




if args.brokenlinks:
    if args.save:
        print(Fore.CYAN + "Saving output to {}".format(args.save))
        commands(f"blc -r --filter-level 2 {args.brokenlinks}")
        if path.exists(f"{args.save}"):
            print(Fore.CYAN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.CYAN + "ERROR!")
    else:
        commands(f"blc -r --filter-level 2 {args.brokenlinks}")
