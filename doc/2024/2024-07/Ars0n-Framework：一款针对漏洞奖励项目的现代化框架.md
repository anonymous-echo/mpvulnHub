#  Ars0n-Framework：一款针对漏洞奖励项目的现代化框架   
Alpha_h4ck  FreeBuf   2024-07-27 09:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
**关于Ars0n-Framework**  
  
  
  
Ars0n-Framework是一款针对漏洞奖励项目的现代化框架，该框架旨在帮助有抱负的研究人员开始他们的漏洞赏金之旅，同时实现一个「边学边赚」的好效果。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR387cLQibZp3odAXgtYrY1vVCDFA4Mpibo2GCKBpTrVo28NpECJcJhqehiaxibFjwTWSgiaNvzLAS8TyENg/640?wx_fmt=png&from=appmsg "")  
  
  
Ars0n-Framework可以给广大安全研究人员和漏洞奖励计划的参与人员提供一个集成式的安全框架，该框架提供了易于使用的自动化工具以及针对各种基于Web和基于云的安全教育内容，并附带了操作指南来降低漏洞奖励计划的准入门槛。这个框架将帮助有抱负的应用安全工程师快速轻松地理解现实世界的安全概念，这些概念直接转化为网络安全领域的高薪职业。  
  
  
**项目机制**  
  
  
##   
  
该项目的灵感来源于Metasploit，因此Ars0n-Framework同样是基于模块化理念设计和开发的。每个脚本（例如：wildfire.py或slowburn.py）基本上都是一个算法，它以特定模式运行模块（例如：fire-starter.py或fire-scanner.py）以获得所需的结果。由于这种设计，社区可以自由构建新脚本来解决特定用例或模块以扩展这些脚本的功能。  
  
  
**工具安装**  
  
  
##   
  
广大研究人员可以直接使用下列命令在  
Kali Linux 2023.4全新版本  
中下载、安装并运行Ars0n-Framework框架的最新稳定版本：  
```
sudo apt update && sudo apt-get update

sudo apt -y upgrade && sudo apt-get -y upgrade

wget https://github.com/R-s0n/ars0n-framework/releases/download/v0.0.2-alpha/ars0n-framework-v0.0.2-alpha.tar.gz

tar -xzvf ars0n-framework-v0.0.2-alpha.tar.gz

rm ars0n-framework-v0.0.2-alpha.tar.gz

cd ars0n-framework

./install.sh
```  
  
需要注意的是，如果你使用的是ARM处理器，则需要添加--arm参数：  
```
./install.sh --arm
```  
  
最新稳定ALPHA版本源码获取：  
```
wget https://github.com/R-s0n/ars0n-framework/releases/download/v0.0.2-alpha/ars0n-framework-v0.0.2-alpha.tar.gz

tar -xzvf ars0n-framework-v0.0.2-alpha.tar.gz

rm ars0n-framework-v0.0.2-alpha.tar.gz
```  
##   
  
**工具使用**  
  
  
##   
### 运行Web应用程序（客户端和服务器）  
  
  
安装完成后，将可以通过输入Y来运行该应用程序。如果选择不立即运行该应用程序，或者需要在重新启动后运行该应用程序，只需直接导航到根目录并运行run.sh脚本：  
```
./run.sh
```  
  
如果你使用的是ARM处理器，则需要添加--arm参数：  
```
./run.sh --arm
```  
### 核心模块  
  
  
Ars0n-Framework的核心模块用于确定基本扫描逻辑。每个脚本都旨在根据用户想要完成的任务支持特定的侦察方法。  
  
  
**Wildfire脚本**  
  
  
Wildfire脚本是Ars0n-Framework中使用最广泛的核心模块。该模块的目的是允许用户扫描多个目标，以便在研究人员发现的任何子域上进行测试：  
```
python3 wildfire.py --start --cloud --scan
```  
  
**Slowburn脚本**  
  
  
Slowburn脚本可以识别目标域名的所有子域名，并从个钟漏洞奖励计划平台API交互通信以手机必要的数据，然后将其存储到本地JSON文件中：  
```
python3 slowburn.py --initialize

python3 slowburn.py
```  
  
**工具使用截图**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR387cLQibZp3odAXgtYrY1vVChibF563rYLPSCn4mq6kIy4PJRVYph05sQavReRyuFscPm0DUythJxBg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR387cLQibZp3odAXgtYrY1vVCwQRb6LS53daEbIlJB7843yibLdAgD6UgiaibrHB6QibUicC8rgFdyoALgPQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR387cLQibZp3odAXgtYrY1vVCwiaHs1tqzg0MLEcuF5QL63zZUMXVBFfDEULtbCSBSG4bCGz4z9H9Iibg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR387cLQibZp3odAXgtYrY1vVC3OGvkB7Sh2XhNcyPeiaNGibEkstMZUu1rBZQBLygTR6o8ay4etZmZ9lg/640?wx_fmt=png&from=appmsg "")  
  
##   
  
**工具演示视频**  
  
  
##   
  
**视频地址：**  
  
https://www.youtube.com/watch?v=cF4xtVS7Rnc  
##   
##   
  
**许可证协议**  
  
  
##   
  
本项目的开发与发布遵循  
MIT  
开源许可协议。  
  
  
**项目地址**  
  
  
  
**Ars0n-Framework：**  
  
https://github.com/R-s0n/ars0n-framework  
  
  
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
> https://www.kali.org/get-kali/#kali-installer-images  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494632&idx=1&sn=39d15121b9d4a665a970768a9b377194&chksm=ce1f1177f9689861d973b98e71492ef76d1894ad7e593b40c27fbdbee4417d4d1a1c24b36621&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494601&idx=1&sn=d02355354ca064cfe25a770b4a650dc8&chksm=ce1f1156f9689840013d9eee16215311ff387b3a0f68cec30ee999a7a00875056790b11052d9&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
