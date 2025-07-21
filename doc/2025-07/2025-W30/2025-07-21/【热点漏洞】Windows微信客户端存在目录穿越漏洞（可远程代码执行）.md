> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247486103&idx=1&sn=ea631f6d34c9881b7185d5b00c5d3f88

#  【热点漏洞】Windows微信客户端存在目录穿越漏洞（可远程代码执行）  
vc  信安百科   2025-07-21 00:01  
  
**0x00 前言**  
  
  
微信客户端是一款基于计算机技术的跨平台即时通讯软件。  
  
  
移动端安卓以Java结合Android SDK开发，iOS 用Objective - C和Swift；PC端 Windows采用C++ 与 Qt框架，Mac则用Objective - C和Swift 。它运用TCP/IP协议经加密与服务器通信，保障安全。  
  
  
数据库存储本地数据，如聊天记录等。采用长连接维持实时消息推送，支持多媒体编解码，实现流畅音视频通话，为全球用户提供便捷通信服务。  
  
  
  
**0x01 漏洞描述**  
  
  
微信客户端在自动下载聊天记录中的文件时，对文件路径的校验和过滤存在不足。  
  
  
攻击者可向目标发送携带恶意文件的聊天消息，当受害者在微信里点击该聊天记录时，恶意文件会被自动下载，且通过目录穿越绕过微信安全限制，被复制到 Windows 系统启动目录。  
  
  
这使得恶意代码得以植入系统关键目录并实现开机自启动。一旦受害者重启电脑，攻击者就能通过该恶意文件在受害系统中执行任意远程代码，从而控制目标系统或维持访问权限。  
  
  
  
**0x02 CVE编号**  
  
  
无  
  
  
  
**0x03 影响版本**  
  
  
微信3.9及以下版本  
  
  
  
**0x04 漏洞详情**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Whm7t4Je6upTXqFtyC4kBsF8jHlicJrtrah7QlRH5LTXH2EZGIOaAZHMKnYy5cpq2iadTL0DSPCSibo9R5YsEibtgw/640?wx_fmt=gif&from=appmsg "")  
  
                                       
（来源于网络）  
  
  
  
**0x05 参考链接**  
  
  
https://weixin.qq.com/  
  
  
  
  
推荐阅读：  
  
  
[安全科普 | 微信出现闪退Bug](https://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247484302&idx=1&sn=91c63f70bff87e7b2f82a2ebb8b2bfae&scene=21#wechat_redirect)  
  
  
  
[安全科普｜渗透测试中的Tips](https://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485142&idx=2&sn=a1c9b9edcaaa7f9d51a3e877403eaef5&scene=21#wechat_redirect)  
  
  
  
[安全科普｜渗透测试中的一些Tips](https://mp.weixin.qq.com/s?__biz=Mzg2ODcxMjYzMA==&mid=2247485118&idx=3&sn=c1c5e6448c5568b7a97ddcda74d97a6b&scene=21#wechat_redirect)  
  
  
  
  
  
Ps：国内外安全热点分享，欢迎大家分享、转载，请保证文章的完整性。文章中出现敏感信息和侵权内容，请联系作者删除信息。信息安全任重道远，感谢您的支持  
![](https://mmbiz.qpic.cn/mmbiz_png/Whm7t4Je6urTIficI8UhQibwpYWx4ic7Bk40AJlXrgx3icofWCbd5cbJFheld132R8exvlHnicn0AUjHLmVok4wV9qA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
！！！  
  
  
**本公众号的文章及工具仅提供学习参考，由于传播、利用此文档提供的信息而造成任何直接或间接的后果及损害，均由使用者本人负责,本公众号及文章作者不为此承担任何责任。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Whm7t4Je6uqQ24S6worK6npevNP8p1uPc9jQeMAib2iaibBnibOzFaIbD0KlvsEtUAmL3xdbJJnWk74Y1KfBcIazzw/640?wx_fmt=png "")  
  
  
