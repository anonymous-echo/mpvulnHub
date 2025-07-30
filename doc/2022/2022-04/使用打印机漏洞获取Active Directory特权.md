#  使用打印机漏洞获取Active Directory特权   
Darkarmour Labs  默安玄甲实验室   2022-04-22 12:52  
  
由于轻量级目录访问协议 (LDAP) 漏洞，黑客可以对具有弱或默认凭据的打印机发起**回传攻击**。这会暴露 Active Directory 用户的登录信息（包括具有管理权限的用户），并可用于进一步控制组织的网络。  
  
“回传攻击”的研究首次出现在foofus.net 上发表的一份文件中。  
  
  
以某打印机为例子。在针对某组织的信息收集后,可以使用未授权访问漏洞或者默认登录凭据访问受影响的打印机的 Web 界面。即使用户名和密码已更改，它们也可能会被暴力破解。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/50Hiagic8dst6Q1WHEAKxjsPoOYXiajGDgpAW8p2Q9P1ZhB7wvGjHZ6xI5zVdD6PckxP2YoImurEfJyBemwpBoLuw/640?wx_fmt=png "")  
  
接下来，找到在设备上配置的 LDAP 连接，并将服务器 IP 地址或主机名更改为他们自己的 IP 地址，如下图所示。由于此打印机固件不需要在更改其服务器地址之前重新输入或验证 LDAP 凭据，因此攻击者可以很好的进行回传攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/50Hiagic8dst6Q1WHEAKxjsPoOYXiajGDgpffX6dicCeF623ygxvZBAlApjboicBMXtfh92wezX20ZICVXYRuTk2erA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/50Hiagic8dst6Q1WHEAKxjsPoOYXiajGDgpY9XBDQ38T2jENtGWiba0iakUPlq5n1qrfzcxh5iaSkkHdrpj1XlcsjxZg/640?wx_fmt=png "")  
  
接下来，攻击者使用诸如 netcat 之类的工具来侦听传入连接并以明文形式显示输出。使用 LDAP 服务器搜索字段，他们可以搜索任何名称并连接到相应的帐户。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/50Hiagic8dst6Q1WHEAKxjsPoOYXiajGDgpicfn5nshj75dd1nMYP9utJzcl4XGtlu5vb24MdianDZzYukRLQC4TibqQ/640?wx_fmt=png "")  
  
我们使用netcat监听获取到了用户名、密码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/50Hiagic8dst6Q1WHEAKxjsPoOYXiajGDgpziaicLl3FLicl051HM6ulD6uyIdN2OicdSwS2mJCFTC4ZY0VwcXrI2y8dQ/640?wx_fmt=png "")  
  
后续可以进一步登录域内用户或者使用密码喷洒获取域内其他机器甚至域控。  
  
  
下表列出了易受上述攻击的打印机以及相应的固件补丁。软件版本较低的设备仍然容易受到攻击，应使用施乐提供的补丁。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/50Hiagic8dst6Q1WHEAKxjsPoOYXiajGDgp8De2CcdTmOXKfZYDiacnOW0jrNKw5TS5WwWv6PGWcPAPmuDia9NveIiaQ/640?wx_fmt=png "")  
  
以下是验证脚本，红队化的工具危害比较大，这边也是提供思路点到即止。  
```
def req_qax(host):

    url1 = host + "/userpost/xerox.sets"
    url2 = host + '/ldap/ldap_list.php?from=protocolConfig'

    param = {

        "_fun_function":'HTTP_Authenticate_fn',
        "NextPage":'/properties/authentication/luidLogin.php',
        "webUsername":'admin',
        'webPassword':'1111',
        'frmaltDomain': 'default',
        'CSRFToken':'641534825d9b951c38e317f8018d399182bf70ab0497220d02e380f97d62b9e0c9fcb16f1ef979341d2fee718c4e9e62df9b4e60d626a121e660e492383724ab'

    }

    url=host+'/properties/authentication/login.php?redir=/ldap/ldap_list.php?from=protocolConfig'
    res=requests.get(url=url,verify=False,headers=headers)
    cookie=str(res.cookies)[37:69]
    cookies = {'PHPSESSID': cookie}
    res = requests.post(url1, headers=headers,data=param,cookies=cookies,verify=False)
    print(res.content)
    if b'roperties/authentication/login.php' in res.content:
        print("error")
    if(b'http_errmsg'  in res.content or b'roperties/authentication/login.php'  in res.content):
        print("登录失败")
    else:
        res2 = requests.get(url=url2, verify=False, cookies=cookies, headers=headers)
        print("---")
        print(res2.content)
        if b'No Servers Configured' in res2.content or ("未配置服务器" in res2.content.decode()):
            print("[-]" + host)
        else:
            print("[+]" + host)
```  
  
同样的类似梭子鱼、HP、RICOH-Network-Printer等设备一样存在此类安全问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/50Hiagic8dst6Q1WHEAKxjsPoOYXiajGDgpThUmEZiaWexesN9hYH2NjgyYM6VVu3CpEZgMp78h3Dnj78TcnsibSMUw/640?wx_fmt=png "")  
  
在上一篇我们谈到了物联网安全漏洞和硬件制造商的松懈控制。本文中介绍的漏洞就是一个很好的例子：**如今，联网设备推向市场的速度超过了它们的安全性，而极少的硬件制造商重视SDL。**这使得许多使用硬件设备组织的安全位置存在盲点，因为许多看似良性的设备（如打印机）为恶意行为者提供了广泛的攻击面。建议多数IOT设备在设计阶段应该使用安全的协议如：ldaps、ftps等。  
  
  
**随着消费级物联网设备的普及和快速增长，安全左移不单单要在普通的web应用实践，更应该瞄准赛博空间中庞大的物联网资产。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/50Hiagic8dst4nP5oz5qtrC3Js9dD8VjEDlPsA7ru4eAkiavKPp4IQjz3OSiaZviclQHIXP96qjib1mMc3ntrkd6a7MA/640?wx_fmt=png "")  
  
  
  
**IoT设备无疑是未来的攻防战场之一，安全左移至关重要。**默安科技提供安全需求分析与威胁建模服务，雳鉴STAC威胁建模系统能够对项目所涉及的业务场景进行多维度威胁评估，输出安全威胁模型、安全需求建议、需求落地方案、需求验证方案等一系列解决方法，快速输出安全需求与设计报告，完成从威胁发现到需求验证的闭环流程。  
  
  
  
参考链接  
  
  
http://foofus.net/goons/percx/praeda/pass-back-attack.pdf  
  
https://securitydocs.business.xerox.com/wp-content/uploads/2020/02/cert_Security_Mini_Bulletin_XRX20D_for_ConnectKey.pdf  
