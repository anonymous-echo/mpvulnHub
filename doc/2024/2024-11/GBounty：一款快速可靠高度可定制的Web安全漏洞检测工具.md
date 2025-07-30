#  GBounty：一款快速可靠高度可定制的Web安全漏洞检测工具   
Alpha_h4ck  FreeBuf   2024-11-12 19:11  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oQ6bDiaGhdyoFWEgZIHic7sqnootFEuOic7RlQNGhKY6d2ZESG3WpiaTMRlD0z4xO6mQrTZjkWHCkMpO2QtCfUJH6g/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**关于GBounty**  
  
  
  
GBounty是一款快速可靠高度可定制的Web安全漏洞检测工具，该工具基于Golang开发，旨在帮助安全测试人员有效识别 Web 应用程序中的潜在问题，并提升Web应用的安全性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibhqydwv1A1angcBN0vjgUaJagN547WM5Y8FllqKZaXAsiajPPo7XMEJ1mk55MsBQp6GIbiclQSEcrg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
除此之外，GBounty还提供了一个  
专门的存储库  
，其中保存了安全研究人员和工程师贡献的各种类型的 Web 漏洞配置文件。  
##   
  
**工具要求**  
  
  
##   
> Go v1.21+环境  
  
##   
  
**工具安装**  
  
  
##   
  
由于该工具基于Golang开发，因此我们首先需要在本地设备上安装并配置好最新版本的Golang环境。  
##   
  
**发布版本**  
  
  
##   
  
直接访问该项目的  
Releases页面  
即可下载预编译的最新版本GBounty。  
###   
### 使用 Go 安装  
  
  
运行以下命令可以直接安装正在开发的最新版本GBounty：  
```
go install -v github.com/bountysecurity/gbounty/cmd/gbounty@main
```  
```
```  
### 源码获取  
  
  
除此之外，广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/BountySecurity/gbounty.git
```  
##   
  
**工具使用**  
  
  
##   
  
下列命令即可查看工具的帮助信息：  
```
gbounty -h
```  
  
  
帮助信息如下：  
```
INFO  GBounty is a multi-step web scanner that uses web vulnerability profiles

 INFO  GBounty profiles can be found at: https://github.com/BountySecurity/gbounty-profiles

 

 

Usage:

  gbounty [flags]

 

Flags:

  -h, --help 显示帮助信息

  --update 更新版本和配置

  --update-app 更新版本

  --update-profiles 更新配置

  --force-update-profiles 强制更新配置文件

 

TARGET INPUT:

  -u, --url value 目标url

  -uf, --urls-file string url列表文件，每行一个url

  -rf, --requests-file string 请求文件地址

 

DEBUG OPTIONS:

  -v, --verbose verbose模式

  -vv, --verbose-extra verbose模式记录额外数据

  -vvv, --verbose-all verbose模式记录全部数据

  -vout, --verbose-output string verbose模式并输出字符串
```  
  
**工具运行演示**  
  
  
```
gbounty -u https://example.org -X POST -d "param1=value1&param2=value2" -t XSS -r 20 -a -o /tmp/results.json --json
```  
```
gbounty --urls-file urls.txt -c 200 -r 10 -p /tmp/gbounty-profiles --silent --markdown -o /tmp/results.md
```  
```
gbounty --raw-request raw_1.txt --raw-request raw_2.txt --blind-host yourblindhost.net
```  
```
gbounty --requests-file requests.zip -r 150 --proxy-address=127.0.0.1:8080 -o /tmp/results.txt --all
```  
```
```  
  
**许可证协议**  
  
  
##   
  
本项目的开发与发布遵循  
MIT  
开源许可协议。  
##   
  
**项目地址**  
  
  
##   
  
**GBounty**：  
  
  
https://github.com/BountySecurity/gbounty  
##   
  
  
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
> https://github.com/bountysecurity/gbounty-profiles  
  
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
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302087&idx=1&sn=29d91904d6471c4b09f4e574ba18a9b2&chksm=bd1c3a4c8a6bb35aa4ddffc0f3e2e6dad475257be18f96f5150c4e948b492f32b1911a6ea435&token=21436342&lang=zh_CN&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302006&idx=1&sn=18f06c456804659378cf23a5c474e775&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
