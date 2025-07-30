#  N/A｜0day！Telegram Windows客户端存在RCE漏洞   
alicy  信安百科   2024-04-13 08:30  
  
**0x00 前言**  
  
****  
Telegram是一款跨平台的即时通讯软件，用户可以相互交换加密与自毁消息，发送照片、影片等所有类型文件。  
  
  
  
**0x01 漏洞描述**  
  
  
官方源文件中写错文件后缀名，  
pyzw写成了pywz  
，攻击者制作恶意的  
.pyzw文件可以在windows中执行任意代码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Whm7t4Je6upgwHkrl6hCicM9r1Jb75d2xphiaP9iau0bOI4MF4icw1RtgIibJ6a7iaFxAdNozBeX8GKlWLzia5yibXk3DA/640?wx_fmt=png&from=appmsg "")  
  
.pyzw是python zip应用程序（zipapp）的文件扩展名。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Whm7t4Je6upgwHkrl6hCicM9r1Jb75d2xU8jb0sYVQ9gML3MiavgYSCdibgRic9PIicseRNvz9J0TYmcK5QGPawOm4Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x02 漏洞利用限制条件**  
  
  
1、windows环境  
  
2、安装有python  
  
  
  
**0x03 漏洞详情**  
  
> pyzw 本质上就是一个zip文件，内附一个__main__.py 打包成zip，并修改为pyzw后缀名，运行文件就会去执行__main__.py里对应的Python代码。  
  
  
  
  
写法一：  
```
__import__("subprocess").call(["calc.exe"])
```  
  
  
写法二：  
```
import subprocess

subprocess.run("calc.exe")
```  
  
  
  
因为漏洞可以结合机器人进行转发，可以使文件变为mp4格式。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Whm7t4Je6upgwHkrl6hCicM9r1Jb75d2xyFiaO88D054ss8gog7mGic7TZzhlZFXl3ClTHmFkvcyhxMJ3ap7B1vgA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
**0x04 参考链接**  
  
  
[安全科普｜0day？网传Telegram桌面版存在RCE漏洞](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485179&idx=4&sn=a36b8cf203797a6ce1722267d11811dd&chksm=cea96f22f9dee63451dc288a0b1c807ed5be8a6cc9950446b3df5ea2e2fe73486984a772206f&scene=21#wechat_redirect)  
  
  
  
[安全研究｜Telegram客户端RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzkyMzI3OTY4Mg==&mid=2247486612&idx=1&sn=502c0430b8f70d49bd56ffa794a0385f&chksm=c1e6c4b9f6914dafcac68c49071be79a80c9af033cdd9716e8a3ff06e13c1719eb22b6d616fd&scene=21#wechat_redirect)  
  
  
  
  
  
推荐阅读：  
  
  
[CVE-2024-3400｜Palo Alto Networks PAN-OS 命令注入漏洞](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485179&idx=1&sn=484e7b82698441e1fb1d962c2c49e823&chksm=cea96f22f9dee6343278e915b81c8c64f5b982f2274788232e51906549b639316211cdd3f127&scene=21#wechat_redirect)  
  
  
  
[CVE-2024-3273｜D-Link NAS设备存在后门帐户（POC）](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485142&idx=1&sn=01ba1dc2f2ccbc5d9711af4bd02beecc&chksm=cea96f0ff9dee6195b10afd3cff3c8db4655bb01d20f0577ce846b0302fdbac633bb1059b9df&scene=21#wechat_redirect)  
  
  
  
[CVE-2024-29202｜JumpServer JINJA2注入代码执行漏洞（POC）](http://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485118&idx=1&sn=71c347bd5af7c9ae26602f892ddbaa97&chksm=cea96f67f9dee6711ccb836b0f407787640eb8609e9688348cd8a19205b80f7de40c3343f78a&scene=21#wechat_redirect)  
  
  
  
  
  
Ps：国内外安全热点分享，欢迎大家分享、转载，请保证文章的完整性。文章中出现敏感信息和侵权内容，请联系作者删除信息。信息安全任重道远，感谢您的支持![](https://mmbiz.qpic.cn/mmbiz_png/Whm7t4Je6urTIficI8UhQibwpYWx4ic7Bk40AJlXrgx3icofWCbd5cbJFheld132R8exvlHnicn0AUjHLmVok4wV9qA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
！！！  
  
  
**本公众号的文章及工具仅提供学习参考，由于传播、利用此文档提供的信息而造成任何直接或间接的后果及损害，均由使用者本人负责,本公众号及文章作者不为此承担任何责任。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Whm7t4Je6uqQ24S6worK6npevNP8p1uPc9jQeMAib2iaibBnibOzFaIbD0KlvsEtUAmL3xdbJJnWk74Y1KfBcIazzw/640?wx_fmt=png "")  
  
  
