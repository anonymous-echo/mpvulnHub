#  msiscan：一款针对msi文件的漏洞检测与识别工具   
Alpha_h4ck  FreeBuf   2024-11-23 02:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oQ6bDiaGhdyoFWEgZIHic7sqnootFEuOic7RlQNGhKY6d2ZESG3WpiaTMRlD0z4xO6mQrTZjkWHCkMpO2QtCfUJH6g/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**关于msiscan**  
  
  
## msiscan是一款针对Microsoft Windows *.msi 安装程序文件的漏洞检测与识别工具，该工具基于Python开发，可以用于获取安装程序的概述并识别潜在的安全问题。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39G3iahheZOC71wg1O78CbDK5PHibuZ2aduFX01jAD6Os5PmpQCL6jQbVjHWdhYAkQNExIYKJSwguYA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
需要注意的是，当前版本的msiscan正处于积极开发中，可能会存在假阳性和假阴性问题。  
##   
  
**工具要求**  
  
  
##   
> Python  
> termcolor  
> msitools  
  
##   
  
**工具安装**  
  
  
##   
  
由于该工具基于Python 3开发，因此我们首先需要在本地设备上安装并配置好最新版本的Python 3环境。  
  
  
接下来，广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/sec-consult/msiscan.git
```  
  
  
然后切换到项目目录中，使用pip命令和项目提供的requirements.txt安装该工具所需的其他依赖组件：  
> cd msiscan  
> pip install -r requirements.txt  
  
  
  
然后安装该工具所需的其他工具包，例如msiinfo和msiextract等：  
```
sudo apt install msitools
```  
##   
  
**工具使用**  
  
  
##   
  
下列命令可以直接扫描检测一个MSI安装文件：  
```
python msiscan.py <Installer>
```  
  
  
下列命令可以直接扫描整个目录：  
```
./runall.sh <directory>
```  
  
  
建议：如果有红色，请使用 ProcMon 修复它并进行手动处理。  
##   
  
**工具运行演示**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39G3iahheZOC71wg1O78CbDKCxwOkjbnns5YCJZQepd5beZ70u1Set7jPpSY8Qs91jWiaxBsO8aA0IQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
##   
  
**许可证协议**  
  
  
##   
  
本项目的开发与发布遵循  
MIT  
开源许可协议。  
##   
  
**项目地址**  
  
  
##   
  
**msiscan**：  
  
  
https://github.com/sec-consult/msiscan  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-38014  
> https://github.com/googleprojectzero/symboliclink-testing-tools/tree/main/SetOpLock  
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651307029&idx=1&sn=809e704f3bd356325cf8d85ed0717a8d&chksm=bd1c2e9e8a6ba788529249c685d4979c6b11853cf8f2d798a6d8e9ce362926ec50e3639cf79f&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651304667&idx=1&sn=d5cc3794a2a9b9626d688c709d261728&chksm=bd1c20508a6ba946471ea1bde2e433eea3f59aa89c656e5e95ac9d2d2a807abfecdca6773d07&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302006&idx=1&sn=18f06c456804659378cf23a5c474e775&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
