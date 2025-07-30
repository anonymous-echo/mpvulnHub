#  Outlook高危远程代码执行漏洞，启明星辰提供解决方案   
 启明星辰集团   2024-02-23 17:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/BwR7Xg3aXhbZjN9t9zxRBVx90nPUBmZJeOnfFc491g0rs9n5vMTcwKHttv947HflXuPXyE6OiaMuoyg8vXFk1jw/640?wx_fmt=gif&from=appmsg "")  
  
  
  
Microsoft Office Outlook是微软开发的办公软件套装中的一个组件，主要功能是收发电子邮件，同时具有管理联系人信息、安排日程、分配任务等功能。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**漏洞详情**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
近日，  
**启明星辰金睛安全研究团队**  
监测到微软二月份安全补丁中一个**CVSS评分为9.8的漏洞**  
（Microsoft Outlook远程代码执行漏洞CVE-2024-21413）POC被公开。  
  
  
经过研究确认，该漏洞绕过了Outlook中的安全限制，导致攻击者只需发送一个钓鱼邮件，即可在受害者**无需任何交互**  
的情况下泄露其NTLM身份凭据信息。通过进一步的破解或者NTLM relay攻击，即可伪造受害者身份进行认证，从而获取对应权限。同时该漏洞在和任意COM漏洞结合使用(如CVE-2022-30190)的时候，攻击者只需诱导受害者  
**点击链接**  
，即可在用户电脑上执行任意代码。  
  
  
该漏洞利用难度较低，与去年被APT28组织频繁利用的Microsoft Outlook 权限提升漏洞(CVE-2023-23397)的攻击场景类似，  
**后续被利用的可能性较高**  
。目前官方已发布安全更新，建议客户积极做好排查和防护。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhYDK5ufTDVocIvRtq86YYSKzmNxTJEOHa6ugCMBFvWomJxvgGCPPaUedpk2ebiaiaghYJA6RT2xboyg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**影响版本**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
- Microsoft
Office LTSC 2021 for 32-bit/64-bit editions  
  
- Microsoft
Office 2019 for 32-bit/64-bit editions  
  
- Microsoft
Office 2016 (32-bit/64-bit edition)  
  
- Microsoft
365 Apps for Enterprise for 32-bit/64-bit System  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
目前已成功复现两种攻击场景。  
  
  
**1、****NTLM泄露**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhYDK5ufTDVocIvRtq86YYSKlMiazSWtjtvibeI2Q1BmYtsaCzZqU1YmwQtaCic1I2WTfOOjUsoQ4mRsg/640?wx_fmt=png&from=appmsg "")  
  
  
**2、****结合其他漏洞触发RCE**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwR7Xg3aXhYDK5ufTDVocIvRtq86YYSKLlQ49UasmibFwm1HibQtfuBlwa70GPAibo8h9d0wRMxumefVreKnN5GAQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhZkJWsvn4MAiaYiaJjkEHZiasrpB2atuLItNKjwjSPXMqvYfMOoiaiagtZEC9I8JaicUghJ0DKorFLqcpNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
**1、官方修复方案**  
  
官方已发布安全更新，建议将受影响的office升级至最新版本：  
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413  
，并且在升级之前不要轻易点击邮件中的链接或附件。  
  
  
**2、启明星辰解决方案**  
  
天阗入侵检测与管理系统、天阗超融合检测探针（  
CSP  
）、天阗威胁分析一体机（  
TAR  
）、天清入侵防御系统（  
IPS  
）可有效防护  
CVE-2024-21413  
漏洞造成的攻击风险。  
此外，天阗威胁分析一体机（  
TAR  
）内置沙箱检测功能，升级到最新补丁可有效检测利用该漏洞的恶意邮件。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BwR7Xg3aXhYDK5ufTDVocIvRtq86YYSK16Yg33nE36GkA96yhGR2m5c7CVo81SPTTiaX2ibOHOynCagetpHK1a0w/640?wx_fmt=jpeg "")  
  
  
  
  
  
  
  
  
•  
  
END  
  
•  
  
  
  
[](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=MzA3NDQ0MzkzMA==&action=getalbum&album_id=1700320980872593410&token=2076503180&lang=zh_CN#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwR7Xg3aXhYyBj2GOibx1omYTmEPTlBPqPP5qNybooG4eeicx9hFJib49ic3Fl9ZjWqWfUcXJqv12ssXdSLSNwKAicg/640?wx_fmt=gif "")  
  
  
