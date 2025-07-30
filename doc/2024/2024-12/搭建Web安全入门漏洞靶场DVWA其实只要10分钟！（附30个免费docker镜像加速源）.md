#  搭建Web安全入门漏洞靶场DVWA其实只要10分钟！（附30个免费docker镜像加速源）   
原创 筑梦网安  全栈安全   2024-12-21 15:25  
  
>   
> 在前期文章《[六大知名Web安全漏洞靶场](https://mp.weixin.qq.com/s?__biz=MzkyMTYyOTQ5NA==&mid=2247485431&idx=1&sn=a8a41e58f8be63da19896c7b97b1bf3f&scene=21#wechat_redirect)  
  
》中我们介绍了漏洞靶场的用途和能力介绍。其中DVWA作为Web安全入门必刷的靶场，包含了最常见的web漏洞，界面简单易用，通过设置不同的难度，可更好地理解漏洞的原理及对应的代码防护。本文详细介绍下如何利用docker快速搭建DVWA漏洞靶场。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicQpW39hicicj4xxtznawOgvC0ydVb4sRrjQI9apO50Cy2suuAicpKiaOgGkOu8P374YM6iaXh2TZ57Qcw/640?wx_fmt=png&from=appmsg "")  
  
知名WEB漏洞靶场  
# 1. 概览  
  
DVWA涉及到多种技术栈，主要有PHP，mariadb，中间件（如apache,nginx等），如果不采用Docker方式安装，整个安装及配置过程会非常麻烦（从下图中可以看出DVWA涉及的安装依赖项），要把靶场手工一步一步搭建并运行起来，至少耗费1个小时。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicQpW39hicicj4xxtznawOgvCAQibQIlibQN1rR0rrHkVZ9Nic4G6X5zupP1zLHVvu3tIkhibE2CpUVjia2g/640?wx_fmt=png&from=appmsg "")  
  
DVWA安装依赖项  
  
但如果采用Docker方式安装可以分钟级搞定，有两种安装方式选择：  
- **使用官方Docker镜像**  
：直接拉取Docker Hub官方镜像运行靶场，预估耗时5min。>>   
>> 缺点：官方镜像是6年前构建的了，后续没有维护更新。  
  
  
- **基于源码构建最新镜像（推荐）**  
：基于DVWA最新代码仓，利用Docker构建出最新镜像并运行靶场，预估耗时15min.>>   
>> 优点：可以运行最新版本的靶场，修复了旧版本中的Bug并新增了部分特性。  
  
  
# 2. 前提条件  
  
电脑上已经安装了Docker环境（比如Docker Desktop，Podman Desktop）。  
  
有了Docker环境后，我们还需要配置镜像加速源（因为国内无法直接使用Docker Hub，据说Docker Hub中存在大量不受管控的恶意镜像源，所以在国内被封禁了）。  
  
不过，大家可以在docker的配置文件（默认径为：/etc/docker/daemon.json  
）中添加如下镜像源（非常全，几乎包含了大家日常用到的所有基础镜像）来实现Docker镜像的拉取：  
```
{    "registry-mirrors": [        "https://do.nark.eu.org",        "https://docker.m.daocloud.io",        "https://docker.1panel.live",        "https://jyr6zqi9.mirror.aliyuncs.com",        "https://dockerproxy.com",        "https://hub-mirror.c.163.com",        "https://mirror.baidubce.com",        "https://reg-mirror.qiniu.com",        "https://docker.mirrors.ustc.edu.cn",        "https://ccr.ccs.tencentyun.com",        "https://mirror.ccs.tencentyun.com",        "https://docker.nju.edu.cn",        "https://docker.mirrors.sjtug.sjtu.edu.cn",        "https://hub.uuuadc.top",        "https://docker.anyhub.us.kg",        "https://dockerhub.jobcher.com",        "https://dockerhub.icu",        "https://docker.ckyl.me",        "https://docker.awsl9527.cn",        "https://hub.fasterdocker.com",        "https://docker.13140521.xyz",        "https://hub.uuuadc.top/",        "https://docker.1panel.live",        "https://hub.rat.dev",        "https://docker.chenby.cn",        "https://docker.hpcloud.cloud",        "https://dislabaiot.xyz",        "https://dockerpull.com",        "https://atomhub.openatom.cn",        "https://docker.kubesre.xyz"    ]}
```  
>   
> Note：以上配置完成后记得要重启Docker服务以让配置文件生效，执行命令service docker restart  
即可重启。  
  
# 3. 安装步骤  
## 3.1. 使用官方Docker镜像  
  
执行如下命令拉取并运行DVWA靶场：  
```
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```  
  
运行成功后有如下提示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicQpW39hicicj4xxtznawOgvC21GxQChhiccPM6vHmts6CjP5rysytWvuO2Wbgia4hhgWDEM3NeDKA4mg/640?wx_fmt=png&from=appmsg "")  
  
运行成功日志  
  
打开浏览器地址栏，输入http://127.0.0.1  
或http://localhost  
会直接跳转到如下登录界面（默认的账户名为：admin，密码为：password）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicQpW39hicicj4xxtznawOgvCMH2icx1uHgu93RcBpNZlDIQVE0U0RoxJRZNUMiaCyibgcbicsgR2WjFV6A/640?wx_fmt=png&from=appmsg "")  
  
登录界面  
  
登录成功后，将页面滚动到最下方，点击“创建/重置数据库”按钮，完成DVWA靶场设置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicQpW39hicicj4xxtznawOgvCayFejDMV6LP2F6icKfEKW2AOey5Yib8icSq5ylrdDRWC62H1S2vXNjHPQ/640?wx_fmt=png&from=appmsg "")  
  
设置DVWA靶场  
  
设置后页面自动跳转到漏洞靶场主页。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicQpW39hicicj4xxtznawOgvCh6nwlnmghmIQT3ibpE57sXP1xrJmziaHibMG4ozQBuuFREMa8w46siaGicw/640?wx_fmt=png&from=appmsg "")  
  
DVWA漏洞靶场主页  
  
执行docker images  
命令，可以看到拉取到本地的所有镜像信息，可以看到DVWA镜像是6年前更新的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicQpW39hicicj4xxtznawOgvC3mb4EH0zV0EtDWbQCQqacYIeczBrsF28cfvLFzLbkGDJib9dxPicK0HA/640?wx_fmt=png&from=appmsg "")  
  
拉取的官方镜像  
  
拉下来我们会介绍如何基于最新代码在本地构建出最新镜像。  
## 3.2. 基于源码构建最新镜像  
  
DVWA开源项目开始于2008年12月，时至今日（2024年）也一直有代码更新，累计Star数已经超过1万。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicQpW39hicicj4xxtznawOgvCgEtoQDzicrynYLpia9W5WG0yicKvCPic8At1DYUkJYaXFdrxicyncAoKA4w/640?wx_fmt=png&from=appmsg "")  
  
2024年代码提交活动图  
  
执行如下命令下载最新代码到本地：  
```
git clone https://github.com/digininja/DVWA.git
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicQpW39hicicj4xxtznawOgvCSh6ts9tPsibcVn6Y5fYyRhvWs4hj3hEBNFor7YjpzZQveq9yCEcRTag/640?wx_fmt=png&from=appmsg "")  
  
克隆代码  
  
切换到代码根目录并构建镜像：  
```
cd DVWAdocker build -t dvwa:latest .
```  
  
这里我们可以看到官方代码中已经增加了compose.yml文件，里面包含两个镜像成分，第一个镜像dvwa:latest  
就是我们上一步刚构建出来的，第二个镜像mariadb:10  
是DVWA网站的后台数据库。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EWVicRs8IibpicQpW39hicicj4xxtznawOgvCqbItSKW0zrdUeGPqJVZrKnicJic0v2xASGNOeycWyATKLicYXRW299jfA/640?wx_fmt=png&from=appmsg "")  
  
compose.yml  
>   
> Note：MariaDB是由MySQL的原始开发者创建的。MariaDB的目的是为了提供一个完全兼容MySQL的替代品，用来避免MySQL被闭源的风险。  
  
  
由于有了compose.yml文件，我们可以直接使用如下命令启动DVWA靶场应用。  
```
docker-compose up d
```  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EWVicRs8IibpicQpW39hicicj4xxtznawOgvClPXttHNGkdZQsibyMCZBYhkvibTXHQaDeH1JMdPTg6zhx4vy5cW5P6MQ/640?wx_fmt=jpeg&from=appmsg "")  
  
运行成功日志  
  
至此，便可直接通过浏览器访问了，拉下来的配置步骤与上一章节（3.1章节）一样，这里便不再赘述。  
  
  
