#  网神SecFox运维安全管理与审计系统 FastJson反序列化RCE漏洞   
Superhero  nday POC   2025-02-08 01:54  
  
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
  
  
网神SecFox运维安全管理  
与审计系统是奇安信网神信息技术（北京）股份有限公司推出的一款重要产品，集“身份认证（Authentication）、账户管理（Account）、权限控制（Authorization）、运维审计（Audit）”于一体。提供统一运维身份认证、细粒度的权限控制、丰富的运维审计报告、多维度的预警方式。为企业提供事前规划、事中控制、事后追溯的整体运维安全能力。采用新一代智能运维技术框架，实现对企事业IT中心的网络设备、数据库、安全设备、主机系统、中间件等资源统一运维管理和审计。通过集中化运维管控、运维过程实时监管、运维访问合规性控制、运维过程图形化审计等功能，为企事业IT中心运维构建一套事前预防、事中监控、事后审计完善的安全管理体系。  
**01******  
  
**漏洞概述**  
  
  
网神SecFox运维安全管理与审计系统 authService接口处使用存在漏洞 fastjson 组件，未授权的攻击者可通过fastjson 序列化漏洞对系统发起攻击获取服务器权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
body="./static/js/vendor.022b3d3adf3423f31f54.js"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkLttUL8ejicfPV7nmxicYTmzFp5WLO5ZVzdn2gdQl3kGZVoiaGrexN3VWWXibgoExaVIFTceIS08j0g/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkLttUL8ejicfPV7nmxicYTm9Cp83sv3Jm5ibJpicLHvicIuiab30L35x4X7h2c5xO4y9EfR3eqL8KU1Dw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkLttUL8ejicfPV7nmxicYTml8V6tG4wiaicF4yTibdbhtlFJ07Hc0xUhSNA9Xq0LNMznqrU9sUr2g4Xg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkLttUL8ejicfPV7nmxicYTmY9zAr3f1wGzNVLvfmgfUo5kR8EObfVIRCsWhibribQ3t2ARRagT1JnGQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLkLttUL8ejicfPV7nmxicYTmNZaALia8ibqd6XW9tXiaTTe9RKmoh0JiadK1Swfp4zp3ZGv0hnpbLEoKKg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
将fastjson组件升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。  
  
2、三款工具都支持内置poc+自写poc目录一起扫描。  
  
3、保持每周更新7-10个左右POC。  
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
