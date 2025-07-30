#  Clair：一款针对应用程序容器的安全漏洞静态分析工具   
Alpha_h4ck  FreeBuf   2024-12-24 10:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**关于Clair**  
  
  
## Clair是一款针对应用程序容器的安全漏洞静态分析工具，该项目完全开源，可以帮助广大研究人员针对应用程序容器（包括OCI和Docker）执行安全漏洞静态分析。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibSxDsItbp8q2DaEq4dPM5d6eLYsjM7IAlFYXibmedxTs11Zia99EvVNN1iaicN2VGZWXic30nuKZJQ00g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Clair的客户端使用 Clair API 来索引他们的容器图像，然后将其与已知漏洞进行匹配。该工具旨在让人们更加透明地了解基于容器的基础设施的安全性。  
##   
  
**功能介绍**  
  
  
  
Clair 支持从以下官方基础容器中提取内容并分分析漏洞：  
> Ubuntu  
> Debian  
> RHEL  
> Suse  
> Oracle  
> Alpine  
> AWS Linux  
> VMWare Photon  
> Python  
  
##   
  
**工具架构**  
  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibSxDsItbp8q2DaEq4dPM5dmfqTXcf28iahF3Xd2wSosALbeW7Q73fB9DUsRib3icmygGvWialpdpV0sQ/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**工具要求**  
  
  
##   
> Go v1.20+  
  
##   
  
**工具安装**  
  
  
##   
  
由于该工具基于Go开发，因此我们首先需要在本地设备上安装并配置好最新版本的Go v1.20+环境。  
###   
### 源码获取  
  
  
广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/quay/clair.git
```  
  
  
然后切换到项目目录中，使用下列命令运行Clair：  
```
cd clair

docker-compose up -d

# or: make local-dev

# or: make local-dev-debug

# or: make local-dev-quay
```  
```
```  
### 发布版本  
  
  
我们还可以访问该项目的  
Releases页面  
下载最新的预编译版本Clair。  
##   
  
**工具使用**  
  
  
##   
### Postgres  
  
  
Clair 使用 PostgreSQL 进行数据持久化。它支持迁移，因此只需将 Clair 指向一个新数据库，然后让它完成设置即可。  
  
  
我们假设已经设置了一个 postgres 数据库，并且可以通过以下连接字符串访问它：  
```
host=clair-db port=5432 user=clair dbname=clair sslmode=disable
```  
###   
### 以组合模式启动Clair  
  
  
Clair的使用有三个前提：  
> 1、指定此实例将以何种模式运行的mode参数或CLAIR_MODE环境变量。  
> 2、指定 Clair 可以在何处找到其配置的conf参数或CLAIR_CONF环境变量。  
> 3、提供 Clair 的配置 yaml 文档。  
  
  
  
如果正在运行容器，则可以挂载Clair 配置并将CLAIR_CONF环境变量设置为相应的路径。  
```
CLAIR_MODE=combo

CLAIR_CONF=/path/to/mounted/config.yaml
```  
  
  
如果直接运行 Clair 二进制文件，最简单的方法是使用命令行：  
```
clair -conf "path/to/config.yaml" -mode "combo"
```  
##   
```
$ clairctl report ubuntu:focal

ubuntu:focal found bash        5.0-6ubuntu1.1         CVE-2019-18276

ubuntu:focal found libpcre3    2:8.39-12build1        CVE-2017-11164

ubuntu:focal found libpcre3    2:8.39-12build1        CVE-2019-20838

ubuntu:focal found libpcre3    2:8.39-12build1        CVE-2020-14155

ubuntu:focal found libsystemd0 245.4-4ubuntu3.2       CVE-2018-20839

ubuntu:focal found libsystemd0 245.4-4ubuntu3.2       CVE-2020-13776

ubuntu:focal found libtasn1-6  4.16.0-2               CVE-2018-1000654

ubuntu:focal found libudev1    245.4-4ubuntu3.2       CVE-2018-20839

ubuntu:focal found libudev1    245.4-4ubuntu3.2       CVE-2020-13776

ubuntu:focal found login       1:4.8.1-1ubuntu5.20.04 CVE-2013-4235

ubuntu:focal found login       1:4.8.1-1ubuntu5.20.04 CVE-2018-7169

ubuntu:focal found coreutils   8.30-3ubuntu2          CVE-2016-2781

ubuntu:focal found passwd      1:4.8.1-1ubuntu5.20.04 CVE-2013-4235

ubuntu:focal found passwd      1:4.8.1-1ubuntu5.20.04 CVE-2018-7169

ubuntu:focal found perl-base   5.30.0-9build1         CVE-2020-10543

ubuntu:focal found perl-base   5.30.0-9build1         CVE-2020-10878

ubuntu:focal found perl-base   5.30.0-9build1         CVE-2020-12723

ubuntu:focal found tar         1.30+dfsg-7            CVE-2019-9923

ubuntu:focal found dpkg        1.19.7ubuntu3          CVE-2017-8283

ubuntu:focal found gpgv        2.2.19-3ubuntu2        CVE-2019-13050

ubuntu:focal found libc-bin    2.31-0ubuntu9          CVE-2016-10228

ubuntu:focal found libc-bin    2.31-0ubuntu9          CVE-2020-6096

ubuntu:focal found libc6       2.31-0ubuntu9          CVE-2016-10228

ubuntu:focal found libc6       2.31-0ubuntu9          CVE-2020-6096

ubuntu:focal found libgcrypt20 1.8.5-5ubuntu1         CVE-2019-12904
```  
  
**许可证协议**  
  
  
##   
  
本项目的开发与发布遵循  
Apache-2.0  
开源许可协议。  
##   
  
**项目地址**  
  
  
##   
  
**Clair**：  
  
  
https://github.com/quay/clair  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://quay.github.io/clair/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651307029&idx=1&sn=809e704f3bd356325cf8d85ed0717a8d&chksm=bd1c2e9e8a6ba788529249c685d4979c6b11853cf8f2d798a6d8e9ce362926ec50e3639cf79f&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651308240&idx=1&sn=96d32c8e6fa90561c84164ed75f4dca0&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
