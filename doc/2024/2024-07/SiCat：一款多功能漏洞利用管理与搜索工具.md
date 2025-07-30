#  SiCat：一款多功能漏洞利用管理与搜索工具   
Alpha_h4ck  FreeBuf   2024-07-04 19:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
**关于SiCat**  
  
  
  
SiCat是一款多功能漏洞利用管理与搜索工具，该工具基于纯Python 3开发，旨在帮助广大研究人员有效地识别和收集来自开源和本地存储库的漏洞信息。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icibtibY92B7JPGmVIkxYSgCwJf66MrJ8sW4IQP8P9iceWvM4Pic6YeSG8PnORmAUImUzzqDopLicWFE9g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
SiCat专注于网络安全管理方面的实践工作，允许研究人员快速实现在线搜索，并查找正在进行的项目或系统中的潜在安全问题和相关漏洞。SiCat的主要优势在于它能够遍历在线和本地资源来收集相关漏洞的信息，能够帮助网络安全专业人员和研究人员了解项目中潜在的安全风险，从而提供宝贵的实践方案以增强系统的安全性。  
  
  
**支持的在线数据源**  
  
##   
> Exploit-DB  
> Packetstorm Security  
> Exploit Alert  
> NVD Database  
> Metasploit Modules  
  
##   
##   
  
**工具要求**  
  
  
##   
> requests==2.25.1  
> colorama==0.4.6  
> xmltodict==0.13.0  
  
##   
##   
  
**工具安装**  
  
  
##   
  
由于该工具基于Python 3开发，因此我们首先需要在本地设备上安装并配置好最新版本的Python 3环境。  
  
  
接下来，广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/justakazh/sicat.git
```  
  
  
然后切换到项目目录中，使用pip命令和项目提供的requirements.txt安装该工具所需的其他依赖组件：  
```
cd sicat

pip install -r requirements.txt
```  
##   
  
**工具使用**  
  
  
##   
  
下列命令即可获取该工具所有支持的参数选项：  
```
~$ python sicat.py --help
```  
### 参数命令解析  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icibtibY92B7JPGmVIkxYSgCwpiaTqqa3DZzsY4dfpl0VOOxAZ7AZfRXVETiaeOwqHIMxA5Xxf0w6q9Xw/640?wx_fmt=png&from=appmsg "")  
##   
  
**工具使用样例**  
  
  
  
根据关键字搜索：  
```
python sicat.py -k telerik --exploitdb --msfmodule
```  
  
  
根据Nmap输出搜索：  
```
nmap --open -sV localhost -oX nmap_out.xml

python sicat.py -nm nmap_out.xml --packetstorm
```  
##   
  
**工具运行演示**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icibtibY92B7JPGmVIkxYSgCwZ293sNMjL4rykuzNWcyvWTUUlTo3Box952K24dvBsYbR4ZvU6FSOqg/640?wx_fmt=png&from=appmsg "")  
  
### 输出报告样例  
###   
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icibtibY92B7JPGmVIkxYSgCwoSe6AMmAl13Hgt0Tvb88zcwytZaW59GbfsRFkfebyTsgHvWR9Qjdow/640?wx_fmt=png&from=appmsg "")  
###   
  
**许可证协议**  
  
  
##   
  
本项目的开发与发布遵循  
MIT  
开源许可协议。  
  
  
**项目地址**  
  
  
  
**SiCat：**  
  
https://github.com/justakazh/sicat  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://www.exploit-db.com/  
> https://packetstormsecurity.com/  
> https://www.exploitalert.com/  
> https://nvd.nist.gov/  
> https://github.com/rapid7/metasploit-framework/tree/master/modules  
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494513&idx=1&sn=d121e4f2e20b5ccd61ecf0ad3d8c2106&chksm=ce1f11eef96898f81380d9a50b1420949d8ab4fb9df77944c1d0a9368a1aa2df63106b75b47b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493976&idx=1&sn=70a35df0a9bd52d9ac09818483ff8810&chksm=ce1f13c7f9689ad10260fd6af11bcf78034d697b75e295281d4d5ce4a941d42ec8a24b9fc044&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
