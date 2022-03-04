import os, requests, time, colorama, socket, instaloader, re, ctypes, uuid, threading , sys, json, httpx, asyncio, logging, random, string, pyshorteners
import socket as ip
from discord_webhook import DiscordEmbed , DiscordWebhook
from colorama import Fore , init
from requests import get
from datetime import datetime
from time import sleep
from tasksio import TaskPool
from bs4 import BeautifulSoup
PU = '\033[1;35;48m'
fw = Fore.WHITE
#============================================================
link = 'https://www.instagram.com/accounts/login/'
login_url = 'https://www.instagram.com/accounts/login/ajax/'
banner1 = get(url="https://pastebin.com/raw/9dWk5YRy").text
bann_ip = get(url="https://pastebin.com/raw/6JyXSr69").text
banner2 = get(url="https://pastebin.com/raw/9zXs75ZN").text
#============================================================
print(f"""{banner1}
      
         [1] IP Tools
         [2] Instagram tools
         [3] Other
         [4] Exit
         """)
panel = input("[+] Choose : ")
if panel=='1':
    os.system("cls")
    print(PU+f"\n{bann_ip}"+fw)
    ip_tools = input("""
    [1] My IP 
    [2] Website IP 
    [3] Exit
    
[+] Choose : """)
    if ip_tools =='1':
        os.system('cls')
        print(PU+f"{banner1}"+fw)
        hostname1 = ip.gethostname()
        qwe = ip.gethostbyname(hostname1)
        print("Your IP is :",qwe)
        print("Your desktop name  is :",hostname1)
        input("Press enter to exit : ")
        print('Good bye..')
        sleep(.6)
        exit()
    if ip_tools =='2':
        os.system('cls')
        print(PU+f"{banner1}"+fw)
        webhost = input("Enter website url : ")
        lord2 = print("website IP is : ", ip.gethostbyname(webhost))
        input("Press enter to exit : ")
        print('Good bye..')
        sleep(.6)
        exit()
    if ip_tools =='3':
        exit()
if panel =='2':
    os.system("cls")
    print(PU+f"\n{banner2}"+fw)
    instagram_tool = input("""
    [1] Instagram account info
    [2] instagram turbo swap 
    [3] sessionid
    [4] Exit
    
[+] Choose : """)
    if instagram_tool =='1':
        os.system('cls')
        print(PU+f"\n{banner2}\n"+fw)
        L = instaloader.Instaloader()
        username=input("[+] Enter username : ")
        profile = instaloader.Profile.from_username(L.context,username)

        count=0
        print('[+] Post : ',profile.mediacount)
        print('[+] Followers : ',profile.followers)
        print('[+] Following : ',profile.followees)
        print("[+] Bio : ",profile.biography)
        print('[+] Profile pic : ',profile.profile_pic_url)
        input("Press enter to exit : ")
        print('Good bye..')
        sleep(.6)
        exit()
    if instagram_tool =='2':
            init(autoreset=True)
            class lordswap:
                def __init__(self):
                    self.sess = requests.session()
                    self.attempts = 0
                    self.green = Fore.LIGHTGREEN_EX
                    self.red = Fore.LIGHTRED_EX
                    self.reset = Fore.RESET
                    self.yellow = Fore.LIGHTYELLOW_EX
                    self.magenta = Fore.LIGHTMAGENTA_EX
                    self.N = 0
                    self.N2 = 0
                    self.uuid = uuid.uuid4()
                    self.headers_instagram_api = {
                        "Host": "i.instagram.com",
                        "Accept": "*/*",
                        "Accept-Encoding": "gzip, deflate",
                        "Accept-Language": "en-US",
                        "User-Agent": "Instagram 123.1.0.26.114 (iPhoneXR)",
                        "X-IG-Capabilities": "3brTvw==",
                        "X-IG-Connection-Type": "WIFI",
                        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                        "Connection": "keep-alive"
                    }
                def http_request(self, url, headers, data=None, cookies=None, post=None, get=None):
                    if post:
                        if data and cookies:
                            return requests.post(url, headers=headers, data=data, cookies=cookies)
                        elif data and not cookies:
                            return requests.post(url, headers=headers, data=data)
                        elif cookies and not data:
                            return requests.post(url, headers=headers, cookies=cookies)
                    elif get:
                        if data and cookies:
                            return requests.get(url, headers=headers, data=data, cookies=cookies)
                        elif data and not cookies:
                            return requests.get(url, headers=headers, data=data)
                        elif cookies and not data:
                            return requests.get(url, headers=headers, cookies=cookies)
                def login(self, username_or_email, password):
                    self.req_login = self.http_request('https://i.instagram.com/api/v1/accounts/login/', self.headers_instagram_api, {"_uuid": self.uuid, "password": password, "username": username_or_email, "device_id": username_or_email, "login_attempt_count":"0", "_csrftoken":"missing"}, False, True, False)
                    if 'logged_in_user' in self.req_login.text:
                        print(f'[{self.magenta}+{self.reset}] Successfully Login > @{username_or_email}')
                        self.cookies_api = self.req_login.cookies
                        self.get_info_account(self.cookies_api)
                    elif 'cha' in self.req_login.text:
                        self.secure(self.cookies_api, self.req_login.json(), username_or_email)
                    else:
                        print(f'{self.req_login.text}\n[{self.magenta}+{self.reset}] Press Enter To Exit')
                        input()
                        exit(0)
                def secure(self, cookies, request_login, username_or_email):
                    self.challenge = request_login['challenge']['api_path']
                    self.get_info_secure = self.http_request(f'https://i.instagram.com/api/v1{self.challenge}', self.headers_instagram_api, False, cookies, False, True).json()
                    try:
                        self.email_secure = self.get_info_secure['step_data']['email']
                    except:
                        print(f'[{self.magenta}+{self.reset}] Not Found Email')
                        self.email_secure = ''
                    try:
                        self.phone_number_secure = self.get_info_secure["step_data"]["phone_number"]
                    except:
                        print(f'[{self.magenta}+{self.reset}] Not Found Phone Number')
                        self.phone_number_secure = ''
                    if not self.email_secure == '' and not self.phone_number_secure == '':
                        print(f'[{self.magenta}+{self.reset}] 1 - {self.email_secure}\n[{self.magenta}+{self.reset}] 2 : {self.phone_number_secure}')
                        self.mode_choice = int(input())
                        if self.mode_choice == 1:
                            self.send_secure = self.http_request(f'https://i.instagram.com/api/v1{self.challenge}', self.headers_instagram_api, {"choice": 1, "_uuid": self.uuid, "_uid": self.uuid, "_csrftoken": "missing"}, cookies, True, False).json()
                            self.contact_point = self.send_secure['step_data']['contact_point']
                            print(f'[{self.magenta}+{self.reset}] Successfully Send Code To {self.contact_point}')
                            print(f'[{self.magenta}+{self.reset}] Code : ', end='')
                            self.code = input()
                            self.check_code = self.http_request(f'https://i.instagram.com/api/v1{self.challenge}', self.headers_instagram_api, {"security_code": self.code, "_uuid": self.uuid, "_uid": self.uuid, "_csrftoken": "missing"}, cookies, True, False)
                            if 'logged_in_user' in self.check_code.text:
                                self.cookies_api = self.check_code.cookies
                                print(f'[{self.magenta}+{self.reset}] Successfully Login > @{username_or_email}')
                                self.get_info_account(self.cookies_api)
                            else:
                                print(f'{self.check_code.text}\n[{self.magenta}+{self.reset}] Press Enter To Exit')
                                input()
                                exit(0)
                        elif self.mode_choice == 2:
                            self.send_secure = self.http_request(f'https://i.instagram.com/api/v1{self.challenge}', self.headers_instagram_api, {"choice": 2, "_uuid": self.uuid, "_uid": self.uuid, "_csrftoken": "missing"}, cookies, True, False).json()
                            self.contact_point = self.send_secure['step_data']['contact_point']
                            print(f'[{self.magenta}+{self.reset}] Successfully Send Code To {self.contact_point}')
                            print(f'[{self.magenta}+{self.reset}] Code : ', end='')
                            self.code = input()
                            self.check_code = self.http_request(f'https://i.instagram.com/api/v1{self.challenge}', self.headers_instagram_api, {"security_code": self.code, "_uuid": self.uuid, "_uid": self.uuid, "_csrftoken": "missing"}, cookies, True, False)
                            if 'logged_in_user' in self.check_code.text:
                                self.cookies_api = self.check_code.cookies
                                print(f'[{self.magenta}+{self.reset}] Successfully Login > @{username_or_email}')
                                self.get_info_account(self.cookies_api)
                            else:
                                print(f'{self.check_code.text}\n[{self.magenta}+{self.reset}] Press Enter To Exit')
                                input()
                                exit(0)
                    elif not self.email_secure == '' and self.phone_number == '':
                        self.send_secure = self.http_request(f'https://i.instagram.com/api/v1{self.challenge}', self.headers_instagram_api, {"choice": 1, "_uuid": self.uuid, "_uid": self.uuid, "_csrftoken": "missing"}, cookies, True, False).json()
                        self.contact_point = self.send_secure['step_data']['contact_point']
                        print(f'[{self.magenta}+{self.reset}] Successfully Send Code To {self.contact_point}')
                        print(f'[{self.magenta}+{self.reset}] Code : ', end='')
                        self.code = input()
                        self.check_code = self.http_request(f'https://i.instagram.com/api/v1{self.challenge}', self.headers_instagram_api, {"security_code": self.code, "_uuid": self.uuid, "_uid": self.uuid, "_csrftoken": "missing"}, cookies, True, False)
                        if 'logged_in_user' in self.check_code.text:
                            self.cookies_api = self.check_code.cookies
                            print(f'[{self.magenta}+{self.reset}] Successfully Login > @{username_or_email}')
                            self.get_info_account(self.cookies_api)
                        else:
                            input("Press enter to exit : ")
                            print('Good bye..')
                            sleep(.6)
                            exit()
                    elif not self.phone_number == '' and self.email == '':
                        self.send_secure = self.http_request(f'https://i.instagram.com/api/v1{self.challenge}', self.headers_instagram_api, {"choice": 2, "_uuid": self.uuid, "_uid": self.uuid, "_csrftoken": "missing"}, cookies, True, False).json()
                        self.contact_point = self.send_secure['step_data']['contact_point']
                        print(f'[{self.magenta}+{self.reset}] Successfully Send Code To {self.contact_point}')
                        print(f'[{self.magenta}+{self.reset}] Code : ', end='')
                        self.code = input()
                        self.check_code = self.http_request(f'https://i.instagram.com/api/v1{self.challenge}', self.headers_instagram_api, {"security_code": self.code, "_uuid": self.uuid, "_uid": self.uuid, "_csrftoken": "missing"}, cookies, True, False)
                        if 'logged_in_user' in self.check_code.text:
                            self.cookies_api = self.check_code.cookies
                            print(f'[{self.magenta}+{self.reset}] Successfully Login > @{username_or_email}')
                            self.get_info_account(self.cookies_api)

                    else:
                        exit(0)
                def get_info_account(self, cookies_api):
                    self.cookies_api = cookies_api
                    self.headers_instagram_web = {"User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36", "x-csrftoken": self.cookies_api["csrftoken"], "x-ig-app-id": "936619743392459", "x-instagram-ajax": "0c15f4d7d44a", "x-requested-with": "XMLHttpRequest"}
                    self.req_get_info = self.http_request('https://www.instagram.com/accounts/edit/?__a=1', self.headers_instagram_web, False, self.cookies_api, False, True).json()
                    try:
                        self.email = self.req_get_info["form_data"]["email"]
                    except:
                        print(f'[{self.magenta}+{self.reset}] Not Found Email')
                        self.email = ''
                    try:
                        self.first_name = self.req_get_info["form_data"]["first_name"]
                    except:
                        print(f'[{self.magenta}+{self.reset}] Not Found First Name')
                        self.first_name = ''
                    try:
                        self.phone_number = self.req_get_info["form_data"]["phone_number"]
                    except:
                        print(f'[{self.magenta}+{self.reset}] Not Found Phone Number')
                        self.phone_number = ''
                    print(f'[{self.magenta}+{self.reset}] Target : ', end='')
                    self.target = input()
                    print(f'[{self.magenta}+{self.reset}] Thread : ', end='')
                    self.thread_n = int(input())
                    ctypes.windll.user32.MessageBoxW(0, f'Click Ok To Start', '#Lord4tb swap', 0)
                    self.threads = []
                    for _ in range(self.thread_n * 10):
                        self.thread_m = threading.Thread(target=self.swapper)
                        self.thread_m.start()
                        self.threads.append(self.thread_m)
                def swapper(self):
                    while 1:
                        try:
                            self.request_swapper_set_username = self.sess.post('https://i.instagram.com/api/v1/accounts/set_username/', headers=self.headers_instagram_api, data={'username': self.target}, cookies=self.cookies_api, timeout=3).status_code
                            if self.request_swapper_set_username == 200 and self.N == 0:
                                self.N = 1
                                print(f'\n[{self.magenta}+{self.reset}] Successfully Swapped : @{self.target}')
                                ctypes.windll.user32.MessageBoxW(0, f'Successfully Swapped : @{self.target}', '#Lord4tb swap', 0)
                                input()
                                exit(0)
                            elif self.request_swapper_set_username == 429 and self.N == 0:
                                self.N = 1
                                print(f'\n[{self.magenta}+{self.reset}] Spam On Set Username')
                            elif self.request_swapper_set_username == 400 and self.N == 0:
                                self.attempts +=1
                                print(f'\r[1] Attempts : {self.attempts}', end='')
                            self.request_swapper_web = self.sess.post('https://www.instagram.com/accounts/edit/', headers=self.headers_instagram_web, data={"first_name": '#Lo4', "email": self.email, "username": self.target, "phone_number": self.phone_number, "biography": 'Successfully Swapped by @ilord4tb, #Lo4', "external_url": "", "chaining_enabled": "on"}, cookies=self.cookies_api, timeout=3).status_code
                            if self.request_swapper_web == 200 and self.N2 == 0:
                                self.N2 = 1
                                print(f'\n[{self.magenta}+{self.reset}] Successfully Swapped : @{self.target}')
                                ctypes.windll.user32.MessageBoxW(0, f'Successfully Swapped : @{self.target}', '#Lord4tb swap', 0)
                                input()
                                exit(0)
                            elif self.request_swapper_web == 400 and self.N2 == 0:
                                self.attempts +=1
                                print(f'\r[2] Attempts : {self.attempts}', end='')
                            class SendDiscord:
                                def __init__(self):
                                    self.url_webhook = 'https://discord.com/api/webhooks/949005978643365888/pD_Cqg6D5eCfUJ1-Txc8Imxb7-xLskwryDu9P8tgtIfXeBiIPHmQjMVE-ZTCh_GGtB2G'
                                def Send(self, username):
                                    self.url = DiscordWebhook(url=self.url_webhook)
                                    self.data_discord = DiscordEmbed(title=f'Successfully Swapped : @{self.target}', color=000000)
                                    self.url.add_embed(self.data_discord)
                                    self.url.execute()
                                    input("Press enter to exit : ")
                                    print('Good bye..')
                                    sleep(.6)
                                    exit()
                        
                        except:
                            pass
            if __name__ == '__main__':
                os.system('cls')
                print(PU+f"\n{banner2}\n"+fw)
                i = lordswap()
                print(f'[{Fore.MAGENTA}+{Fore.RESET}] Username Or Email : ', end='')
                username_or_email = input()
                print(f'[{Fore.MAGENTA}+{Fore.RESET}] Password : ', end='')
                password = input()
                i.login(username_or_email, password)
    if instagram_tool =='3':
        os.system('cls')
        print(PU+f"\n{banner2}\n"+fw)
        time = int(datetime.now().timestamp())
        user = input('[+] Enter username : ')
        pwd = input('[+] Enter password : ')
        payload = {
            'username': ''+user+'',
            'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:{time}:{pwd}',
            'queryParams': {},
            'optIntoOneTap': 'false'
        }

        with requests.Session() as s:
            r = s.get(link)
            csrf = re.findall(r"csrf_token\":\"(.*?)\"",r.text)[0]
            r = s.post(login_url,data=payload,headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": "https://www.instagram.com/accounts/login/",
                "x-csrftoken":csrf
            })
        print('')
        print('')
        print(s.cookies)
        input("Press enter to exit : ")
        print('Good bye..')
        sleep(.6)
        exit()
    if instagram_tool =='4':
        exit()
if panel =='3':
    os.system("cls")
    print(PU+f"\n{banner1}"+fw)
    print(f"\n    [",PU+'1'+fw,"]", "Tiktok autoclaimer ")
    print(f"    [",PU+'2'+fw,"]", "Password list maker ")
    print(f"    [",PU+'3'+fw,"]", "Discord Token Generator ")
    print(f"    [",PU+'4'+fw,"]", "short url ")
    print(f"    [",PU+'5'+fw,"]", "Exit ")

    ot_tools = input("""
[+] Choose : """)
    os.system('cls')
    print(PU+f"\n{banner1}"+fw)
    if ot_tools =='1':
        logging.basicConfig(
        level=logging.INFO,
        format="\u001b[36;1m[\u001b[0m%(asctime)s\u001b[36;1m]\u001b[0m %(message)s\u001b[0m",
        datefmt="%H:%M:%S"
    )
        class TikTok(object):

            def __init__(self):
                os.system("cls")
                print(PU+f"\n{banner1}"+fw)
                self.attempts = 0
                self.checking = True
                self.first_req = True

                self.webhook = input("[+] Webhook : ")
                self.nickname = input("[+] Nickname : ")
                self.signature = input("[+] Signature : ")

                self.target = input("[+] Target : ")
                self.session_id = input("[+] Session ID : ")
                self.x_token = input("[+] X-Token : ")
                self.threads = int(input("[+] Threads : "))

                print()

            async def _webhook(self):
                payload = {
                "username": "Lord4tb TikTok Autoclaimer",
                "avatar_url": "https://www.ualberta.ca/youalberta/media-library/2021/jjk-gif1.gif",
                "embeds": [
                    {
                        "description": "Successfully claimed %s after %s requests" % (self.target, self.attempts),
                        "color": 0xf62b52,
                        "thumbnail": {
                            "url": "https://www.ualberta.ca/youalberta/media-library/2021/jjk-gif1.gif"
                        }
                        }
                    ]
                }
                if not self.webhook == "":
                    try:
                        async with httpx.AsyncClient() as client:
                            await client.post(self.webhook, json=payload)
                    except Exception:
                        pass

            async def _update(self):
                query = {
                    "iid":"7025240856680744710",
                    "device_id":"6906478625937278469",
                    "ac":"wifi",
                    "channel":"googleplay",
                    "aid":"1233",
                    "app_name":"musical_ly",
                    "version_code":"210605",
                    "version_name":"21.6.5",
                    "device_platform":"android",
                    "ab_version":"21.6.5",
                    "ssmix":"a",
                    "device_type":"A5010",
                    "device_brand":"OnePlus",
                    "language":"en",
                    "os_api":"25",
                    "os_version":"7.1.2",
                    "openudid":"c0575264c704f9c6",
                    "manifest_version_code":"2022106050",
                    "resolution":"1280*720",
                    "dpi":"240",
                    "update_version_code":"2022106050",
                    "_rticket":"1635699028787",
                    "current_region":"US",
                    "app_type":"normal",
                    "sys_region":"US",
                    "mcc_mnc":"31031",
                    "timezone_name":"Asia/Shanghai",
                    "residence":"US",
                    "ts":"1635699032",
                    "timezone_offset":"28800",
                    "build_number":"21.6.5",
                    "region":"US",
                    "uoo":"0",
                    "app_language":"en",
                    "carrier_region":"US",
                    "locale":"en",
                    "op_region":"US",
                    "ac2":"wifi",
                    "cdid":"c7486e9b-720c-4c53-b01e-b48e1627212c",
                    "support_webview":"1",
                    "okhttp_version":"4.0.61.8-tiktok"
                }
                payload = "signature=%s&nickname=%s&confirmed=0&uid=7026441925374657583&page_from=0" % (self.signature, self.nickname)
                headers = {
                    "x-ss-stub": "42DC863028F620DC41672CD338EB44A4",
                    "accept-encoding": "gzip",
                    "passport-sdk-version": "19",
                    "sdk-version": "2",
                    "x-tt-multi-sids": "7025753269597127726%3Adfcf3163978d7473f4265b7985a97c8b%7C6878277293988398082%3A244ead388a50153c26ac6fc1acc952cf%7C6798526938606273542%3A22ffb97374208354f611434830978268%7C7026142094618723374%3A2ba5159cd3831bb558b0d2b9e6956d2d%7C7026413601490617390%3A0baebad63036d3d61d7299db3e405ca5%7C7026419283280331822%3A2b9d3689fc25bdd2a31eb5f9986895c0",
                    "x-tt-token": self.x_token,
                    "multi_login": "1",
                    "x-ss-req-ticket": "1635969272581",
                    "x-bd-client-key": "#Rzymagg36Y5cBIsrKQVP4afsyk58gCfUIKoRifwyk0hpXouT5vJYFruOdYbI34RHdv8dom3KGjMPJCRQ",
                    "x-bd-kmsv": "0",
                    "x-vc-bdturing-sdk-version": "2.1.0.i18n",
                    "x-tt-dm-status": "login=1;ct=1rt=1",
                    "x-tt-cmpl-token": "AgQQAPNSF-RPsLG8NbvG090XxbkkhHRO_4fZYMOUng",
                    "x-tt-store-idc": "maliva",
                    "x-tt-store-region": "us",
                    "x-tt-store-region-src": "uid",
                    "user-agent": "com.zhiliaoapp.musically/2022107090 (Linux; U; Android 7.1.2; en_US; A5010; Build/N2G48H;tt-ok/3.10.0.2)",
                    "cookie": "sessionid=%s" % (self.session_id),
                    "x-tt-passport-csrf-token": self.session_id,
                    "x-ladon": "cz9ecBKrtwxN1+X3z7aoUiUDuxNDEuj0RHFnT+JAHadKAF5K",
                    "x-gorgon": "0404e0924005cc3f5647c07af65bfe3c96bebe12f47d79753870",
                    "x-khronos": "1635969272",
                    "x-argus": "TwNbYJjqKLgLkeAm4oPdfvHLyLQSIcmtbB/y68LCkl9UTFJ3OywZaUx5CQcv3fAwp7T7+wZIKs9z8LsJ3ss1ADanZj/BhytTS08tpkiOtm3JT7JExg9sMxI4cB5axU34IxuvI7HWrcqCt6xESX3tpr1SalM7iOyDyk7a4YVELtbxOsbixiYgc1OMQNJnF4ekmzcCHVBkzl4aXspjK3D5BPc/sWJ3FNj0vHUI8nv+rhLDPKD69YRbPAjLppF2FSw1u04RVCRN4vnWGKmhX0OQFScW+nas+noQH2Glr6etJwXus+5X+ahJMaq3n9NU+LHCaM5ZAvmD0DEvxtWN9TNRAynoShF6l2A+IXZUTvtU+UHYHw==",
                    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "host": "api22-normal-c-useast1a.tiktokv.com",
                    "connection": "Keep-Alive"
                }
                try:
                    async with httpx.AsyncClient() as client:
                        response = await client.post("https://api22-normal-c-useast1a.tiktokv.com/aweme/v1/commit/user/", data=payload, headers=headers, params=query)
                        if not "nickname" in response.text:
                            logging.error("Invalid session/x-token specified.")
                            sys.exit()
                        else:
                            logging.info("Successfully logged into %s" % (response.json()["user"]["unique_id"]))
                except Exception:
                    pass

            async def _claim(self):
                query = {
                    "iid":"7025240856680744710",
                    "device_id":"6906478625937278469",
                    "ac":"wifi",
                    "channel":"googleplay",
                    "aid":"1233",
                    "app_name":"musical_ly",
                    "version_code":"210605",
                    "version_name":"21.6.5",
                    "device_platform":"android",
                    "ab_version":"21.6.5",
                    "ssmix":"a",
                    "device_type":"A5010",
                    "device_brand":"OnePlus",
                    "language":"en",
                    "os_api":"25",
                    "os_version":"7.1.2",
                    "openudid":"c0575264c704f9c6",
                    "manifest_version_code":"2022106050",
                    "resolution":"1280*720",
                    "dpi":"240",
                    "update_version_code":"2022106050",
                    "_rticket":"1635699028787",
                    "current_region":"US",
                    "app_type":"normal",
                    "sys_region":"US",
                    "mcc_mnc":"31031",
                    "timezone_name":"Asia/Shanghai",
                    "residence":"US",
                    "ts":"1635699032",
                    "timezone_offset":"28800",
                    "build_number":"21.6.5",
                    "region":"US",
                    "uoo":"0",
                    "app_language":"en",
                    "carrier_region":"US",
                    "locale":"en",
                    "op_region":"US",
                    "ac2":"wifi",
                    "cdid":"c7486e9b-720c-4c53-b01e-b48e1627212c",
                    "support_webview":"1",
                    "okhttp_version":"4.0.61.8-tiktok"
                }
                payload = "uid=7025085796388963374&login_name=%s&page_from=0" % (self.target)
                headers = {
                    "x-ss-stub": "42DC863028F620DC41672CD338EB44A4",
                    "accept-encoding": "gzip",
                    "passport-sdk-version": "19",
                    "sdk-version": "2",
                    "x-tt-multi-sids": "7025753269597127726%3Adfcf3163978d7473f4265b7985a97c8b%7C6878277293988398082%3A244ead388a50153c26ac6fc1acc952cf%7C6798526938606273542%3A22ffb97374208354f611434830978268%7C7026142094618723374%3A2ba5159cd3831bb558b0d2b9e6956d2d%7C7026413601490617390%3A0baebad63036d3d61d7299db3e405ca5%7C7026419283280331822%3A2b9d3689fc25bdd2a31eb5f9986895c0",
                    "x-tt-token": self.x_token,
                    "multi_login": "1",
                    "x-ss-req-ticket": "1635969272581",
                    "x-bd-client-key": "#Rzymagg36Y5cBIsrKQVP4afsyk58gCfUIKoRifwyk0hpXouT5vJYFruOdYbI34RHdv8dom3KGjMPJCRQ",
                    "x-bd-kmsv": "0",
                    "x-vc-bdturing-sdk-version": "2.1.0.i18n",
                    "x-tt-dm-status": "login=1;ct=1rt=1",
                    "x-tt-cmpl-token": "AgQQAPNSF-RPsLG8NbvG090XxbkkhHRO_4fZYMOUng",
                    "x-tt-store-idc": "maliva",
                    "x-tt-store-region": "us",
                    "x-tt-store-region-src": "uid",
                    "user-agent": "com.zhiliaoapp.musically/2022107090 (Linux; U; Android 7.1.2; en_US; A5010; Build/N2G48H;tt-ok/3.10.0.2)",
                    "cookie": "sessionid=%s" % (self.session_id),
                    "x-tt-passport-csrf-token": self.session_id,
                    "x-ladon": "cz9ecBKrtwxN1+X3z7aoUiUDuxNDEuj0RHFnT+JAHadKAF5K",
                    "x-gorgon": "0404e0924005cc3f5647c07af65bfe3c96bebe12f47d79753870",
                    "x-khronos": "1635969272",
                    "x-argus": "TwNbYJjqKLgLkeAm4oPdfvHLyLQSIcmtbB/y68LCkl9UTFJ3OywZaUx5CQcv3fAwp7T7+wZIKs9z8LsJ3ss1ADanZj/BhytTS08tpkiOtm3JT7JExg9sMxI4cB5axU34IxuvI7HWrcqCt6xESX3tpr1SalM7iOyDyk7a4YVELtbxOsbixiYgc1OMQNJnF4ekmzcCHVBkzl4aXspjK3D5BPc/sWJ3FNj0vHUI8nv+rhLDPKD69YRbPAjLppF2FSw1u04RVCRN4vnWGKmhX0OQFScW+nas+noQH2Glr6etJwXus+5X+ahJMaq3n9NU+LHCaM5ZAvmD0DEvxtWN9TNRAynoShF6l2A+IXZUTvtU+UHYHw==",
                    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "host": "api22-normal-c-useast1a.tiktokv.com",
                    "connection": "Keep-Alive"
                }
                try:
                    async with httpx.AsyncClient() as client:
                        response = await client.post("https://api22-normal-c-useast1a.tiktokv.com/passport/login_name/update/", data=payload, headers=headers, params=query)
                        if "success" in response.text:
                            logging.info("Successfully claimed \u001b[36;1m(\u001b[0m%s\u001b[36;1m)\u001b[0m" % (self.target))
                            await self._webhook()
                            sys.exit()
                        else:
                            logging.error("%s \u001b[36;1m(\u001b[0m%s\u001b[36;1m)\u001b[0m" % (response.json()["data"]["description"], self.target))
                            sys.exit()
                except Exception:
                    logging.error("Unable to claim \u001b[36;1m(\u001b[0m%s\u001b[36;1m)\u001b[0m" % (self.target))
                    sys.exit()

            async def _worker(self):
                while True:
                    headers = {
                        "Host": "api19-normal-c-useast1a.tiktokv.com",
                        "Connection": "keep-alive",
                        "x-Tt-Token": "012a6b6d6f0ca859868c920bed0fbc89de00dc324a56c811a80996dd798c7aa36503752930344e7b10db7fed42a72a4149da3907477f89775bfae0244a20fe48ef254133b42c049f24deb2121b9197cd17e8c-1.0.0",
                        "sdk-version": "2",
                        "User-Agent": "com.zhiliaoapp.musically/2022106020 (Linux; U; Android 7.1.2; en_US; Build/N2G48H;tt-ok/3.10.0.2)",
                        "x-tt-store-idc": "alisg",
                        "x-tt-store-region": "de",
                        "Accept-Encoding": "gzip, deflate"
                    }
                    try:
                        async with httpx.AsyncClient() as client:
                            response = await client.get("https://api19-normal-c-useast1a.tiktokv.com/aweme/v1/unique/id/check/?unique_id=%s&iid=7026260912928425734&device_id=7026260845073188357&ac=wifi&channel=googleplay&aid=1233&app_name=musical_ly&version_code=210602&version_name=21.6.2&device_platform=android&ab_version=21.6.2&ssmix=a&device_type=SM-N975F&device_brand=samsung&language=en&os_api=25&os_version=7.1.2&openudid=f0bfccc997a123b5&manifest_version_code=2022106020&resolution=720*1280&dpi=240&update_version_code=2022106020&_rticket=1636035582804&current_region=NZ&app_type=normal&sys_region=US&mcc_mnc=53001&timezone_name=Asia Shanghai&residence=NZ&ts=1636035582&timezone_offset=28800&build_number=21.6.2&region=US&uoo=0&app_language=en&carrier_region=NZ&locale=en&op_region=NZ&ac2=wifi&cdid=8a438d2e-2dea-4dc4-b7a9-ffa83828570e" % (self.target), headers=headers, timeout=5)
                            self.attempts += 1
                            if not self.attempts % 100: logging.info("Sent %s request attempts" % (self.attempts))

                            if "is_valid" in response.text:
                                if response.json()["is_valid"]:
                                    self.checking = False
                                    return await self._claim()
                    except Exception:
                        pass

            async def start(self):
                logging.info("Starting autoclaimer!")
                await self._update()
                async with TaskPool(self.threads) as pool:
                    while self.checking:
                        await pool.put(self._worker())

        if __name__ == "__main__":
            client = TikTok()
            asyncio.get_event_loop().run_until_complete(client.start())
    if ot_tools =='2':
            os.system('cls')
            print(PU+f"\n{banner1}"+fw)
            chars = 'abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()_+QWERTYUIOP}{ASDFGHJKLZXCVBNM,./;~`'
            password = ''
            length = input("Enter Password Length : ")
            length = int(length)
            for c in range(length):
                password += random.choice(chars)
                sleep(0.2)

            print(password)
            input("Press enter to exit : ")
            print('Good bye..')
            sleep(.6)
            exit()
    if ot_tools =='3':
        os.system('cls')
        print(PU+f"\n{banner1}"+fw)
        ra = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm0123456789"
        start = input("Press Enter to start : ")

        for i in range(1000):
            fi = ''.join((random.choice(ra) for i in range(26)))
            sec = ''.join((random.choice(ra) for i in range(6)))
            th = ''.join((random.choice(ra) for i in range(27)))

            re = fi + "." + sec + "." + th
            print(PU+f'',re+fw)
            file = open("Token_Generator.txt", "a")
            file.write(re + "\n")
    if ot_tools =='4':
        def Shorten(url):
            link = pyshorteners.Shortener()
            return link.tinyurl.short(url)

    if __name__ == "__main__":
        url = input("Enter url : ")
        print(f"\n{Shorten(url)}")
    if ot_tools =='5':
        exit()