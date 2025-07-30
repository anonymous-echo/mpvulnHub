#  实战 | 教育SRC漏洞挖掘获取rank以及证书获取   
 天启互联网实验室   2024-04-07 20:23  
  
在2023年3月份的时候写了一篇【[教育src漏洞挖掘获取rank以及证书获取](http://mp.weixin.qq.com/s?__biz=Mzg5NDU3NDA3OQ==&mid=2247488705&idx=1&sn=5e1d67e00b307a6b8350c1749d3c394a&chksm=c01cd851f76b514762a479b28b4c4fb2cd1116f4aca9fd0e77813ebf68fc7cd91555b8568c3f&scene=21#wechat_redirect)  
  
】的文章，  
主要是说了如何进行漏洞挖掘获取足够多的积分，时隔一年，这次说说怎么快速获取证书站的漏洞！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/0YvAy5BgkyPZ27CxofDnicwL1FChhIXoUV9VpYpfQZgwgeQ5SJGibg7d0RIN19UViaFPzngD2D2Wg1ooPzZia7ibibOg/640?wx_fmt=jpeg&from=appmsg&wxfrom=13 "")  
  
**守株待兔法**  
  
将有证书学校的站点的重要资产先收集起来，等到别人发1day或者未公开的day时，可以在收集的资产中进行检索，查看资产中是否存在此漏洞。如果存在，则可以快速提交。这个有点看手速。手疾眼快！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/0YvAy5BgkyPZ27CxofDnicwL1FChhIXoUtUpaCz3kTNu5LVk9CVD4oGpuZIDGcNVLQdxo0kUz5yrWuqQ8WmuGgg/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**主动进攻法**  
  
**证书学校的选取**  
  
可以先了解每个证书的获取条件，可优先选取一些难度较小的学校进行漏洞挖掘。  
  
如下图，该学校的证书相对于来说就比较难，需要三个中危及其以上级别的漏洞，对于想快速获取证书的同学来说，选择这个不是一个明智的选择。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPZ27CxofDnicwL1FChhIXoUns35afWnZnNODia4I7eHwmXsHWf4vOPlG7vb36KXBSsGfRGCXvz0L7w/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
确定好了目标后可以去看看该学校的漏洞类型分布图，可以看到这个学校比较多的是弱口令漏洞以及敏感信息泄漏漏洞。那我们挖掘的侧重点也可以。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPZ27CxofDnicwL1FChhIXoUzEbECddo238p2xWtbPcmc9fIY7eXht1RWf2YIsCTMRhNHGr5tSrxCA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
常规的就是对web站点进行渗透测试，  
信息收集（占主要）、漏洞挖掘。  
  
web站点渗透结束无果时，可以考虑对小程序以及app进行测试  
  
**新媒体信息收集**  
  
**方式1：**  
  
直接  
微信默认搜索  
直接怼进去  
注意一下**公众号 小程序 公司名称主体**  
 可以  
更换字眼搜索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPZ27CxofDnicwL1FChhIXoUqMqdpDnwkOFWDSBxdwv3kd8oQO1gwqRrr3tkOicXB2zWiaHvowFQ7r5A/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 方式2:  
  
天眼查、企查查、爱企查 等等  
  
这里推荐小蓝本:  
https://sou.xiaolanben.com/pc  
  
可以直接新媒体能查到公司旗下有哪些公众号小程序或者APP  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPZ27CxofDnicwL1FChhIXoUGHdwF3ibMkuLiaCkl5LUY6CT4APy4DVCSKNsKiazibC7qiaUhgXaR8DkiaDg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**方式3:**  
  
有做过微信公众号运营的同学应该知道，其实可以去找一些**微信公众号数据分析平台**  
也可以作为我们信息收集的工具  
。这些数据分析平台收录的微信公众号和小程序非常多，信息收集搜索其实完全够用了。  
  
**小程序渗透测试**  
  
抓包问题：下载proxyman简单配置即可，适合不愿意折腾配置的师傅。  
  
打开此抓包软件，mac中打开小程序即可在抓包软件的应用程序->WeCaht Networking下查看小程序的数据包，进行愉快的测试。windows同理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPZ27CxofDnicwL1FChhIXoUWFJEVicXGwvicj5I58KqfvckibkUeamMAscYWmib3Wic6ZTbsrtUoibWnuJg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
小程序反编译查找一些敏感信息泄漏，例如：  
Accesskey泄露。  
  
一些osskey、oss存储桶、账号密码信息等写死在了小程序里面，通过反编译可以直接找到这些信息。  
  
关键字：oss、accesskey等  
  
这种漏洞很简单，其实无论是小程序还是app，都是硬编码导致的漏洞。  
  
微信小程序反编译工具的一些工具：  
```
https://github.com/ezshine/wxapkg-convertor
https://data.hackinn.com/tools/wxappUnpacker.zip
```  
  
**app渗透测试**  
  
**如何抓包：**  
安卓小黄鸟+平行大师(模拟器和手机同理)  
  
**小黄鸟**  
本名称“HttpCanary”，是一款功能全面的数据抓取软件，现已支持HTTP/HTTPS 1.0和1.1协议和HTTP2协议以及其他TCP协议。而且无需root便能详细的显示出每个你想要管控的应用的消耗流量情况，并还内置了静态注入以及动态注入以及等多种的浏览视图功能，非常实用简洁。  
```
安装好小黄鸟和平行大师

在平行大师中克隆需要的应用

打开小黄鸟，选取平行大师即可抓取数据包
```  
  
通过抓包可测试一些常见漏洞  
  
**反编译app**  
  
利用该项目直接对app进行反编译：  
  
https://github.com/skylot/jadx  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPZ27CxofDnicwL1FChhIXoUS3mNRaHVkdxrqZuOZuYlzklSevj0MPUEOR6zuSmjQMOO5c0CTicl7hw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
寻找信息泄露，  
搜索secret关键词：  
  
常见的敏感词有access，accesskey，accessid，secret，appid，password等都可以进行搜索。  
  
对于app渗透来讲，一般反编译之后首先要找一些敏感的变量，因为很多app都和云服务器，小程序，公众号或者其他的第三方平台都有一定的关系，通过获取这些平台的接口进而来获有关云方面的权限也是一种常用的方法。  
  
笔者这里也是在两天内通过小程序挖取到两个证书站的漏洞获取到相应的证书。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0YvAy5BgkyPZ27CxofDnicwL1FChhIXoUG12LTyqAfaUOw6SiaIrQ0icx3M4se6HY8AsmQJrGrUNa9ORjicTGT3ia2w/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
硬实力强悍的师傅可采用代码审计法，可审计一些主流OA，如：通达、泛微、致远等等。  
  
