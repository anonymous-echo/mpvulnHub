#  Elber-Wayber模拟数字音频密码重置漏洞   
Superhero  Nday Poc   2025-03-08 16:35  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
Elber wayber 是一家专注于音频技术解决方案的公司，提供高质量的模拟和 数字音频Q设备，广泛应用于专业录音、广播、现场演出和多媒体制作等领域。其产品以卓越的音质、稳定的性能和用户友好的设计著称，深受音频工程师和音乐制作人的青睐。Elber wayber致力于通过创新的技术和高标准的制造工艺，为用户提供可靠的音频工具，帮助他们实现卓越的音频体验。  
**01******  
  
**漏洞概述**  
  
  
Elber wavber 模拟/数字音频系统,存在一个严重的安全漏洞，该漏洞位于系统的密码重置功能中。攻击者可以通过利用此漏洞。绕过正常的身份验证流程，直接重置用户密码，从而非法获取系统访问权限。一旦攻击者成功重置密码，他们可以登录系统并完全接管控制权，进而窃取敏感数据、篡改系统设置或进行其他恶意操作。   
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
title="Elber Satellite Equipment" || body="www.elber.it"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLcyxr8sf0RmTjrdOGC5SnXhGviaz7bt1ibA0uzX0D8FEs8BQoqPZgIjTCA5REHB3T07LNQ3Kn4iaNnw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLcyxr8sf0RmTjrdOGC5SnXbOSv3xx6FwujJexJssomhcPkbpZNk9SibW1Ke184kkBqN0HNyRZCH8g/640?wx_fmt=png&from=appmsg "")  
  
验证admin/  
ubtmjl  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLcyxr8sf0RmTjrdOGC5SnX6YlJgTbZLvLdrcncMIDTz7LkicjLGKHlyibIBnpGOb38PSGP0ibHic2WBg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLcyxr8sf0RmTjrdOGC5SnXDomQTW5Rw1paGywwPRFTqtgv47Q2TUKoRHQpWIxQLicVHT7pauqu5jg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLcyxr8sf0RmTjrdOGC5SnX4aEa92ibtO6bEHc0wrdpIjUThF6EKicFlVK52lh0bEHhk8o2g9cVSWzg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLcyxr8sf0RmTjrdOGC5SnXGDNMKQialqKVsswfbanicWauv5Sz982Ht1AqLtoJSYrwXKRnOSfvhajQ/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新7-10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
