> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMTcwMTg1Mg==&mid=2247491980&idx=1&sn=0425e1ac6aba4303cd7fb98b6307bc55

#  红帆OA MobileOA.asmx SQL注入漏洞  
Superhero  Nday Poc   2025-07-01 08:54  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号Nday Poc及作者不为此承担任何责任，一旦造成后果请自行承担！  
  
  
**01**  
  
**漏洞概述**  
  
  
由于红帆OA MobileOA.asmx接口处未对用户的输入进行过滤和校验，未经身份验证的攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:  

```
app=&#34;红帆-ioffice&#34;
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLrz2n2qnCyVBkmMYx9pibTpYibqFzSxmqTnYfiaTEicr0JvcDRjlz5V2LbCjRWY0Kz7EkUUkica8bNw6A/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLrz2n2qnCyVBkmMYx9pibTpYPbGaficlFpWlq8g8FgeKYDlOgmXVxm395E9cE9tWwZBzBMMFicsN9dA/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLrz2n2qnCyVBkmMYx9pibTpIhAfupOYJIlmAOsKsrmt6vvR7kultibfOypbB7BSlnpn14XeZibMY6LQ/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLrz2n2qnCyVBkmMYx9pibTpE4WOEQEyl2QB42R7S7I6Qruk8wHhDG2SCUoTXtxsyMVLiaBAMMavO7Q/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLrz2n2qnCyVBkmMYx9pibTp9lVuTz7XpiaUqeFZCUYFHmGoHzf376UgqY4h2dUCe79xQt26VeCgWXQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLrz2n2qnCyVBkmMYx9pibTpWWSIfYYUTOz6RyicvWdiaHBFql5yswJ8ehK11Dcp39fxEKCZ9icTICJ1A/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、升级至安全版本  
  
  
**06******  
  
**内部圈子介绍**  
  
  
【Nday漏洞实战圈】🛠️   
  
专注公开1day/Nday漏洞复现  
 · 工具链适配支持  
  
 ✧━━━━━━━━━━━━━━━━✧   
  
🔍 资源内容  
  
 ▫️ 整合全网公开  
1day/Nday  
漏洞POC详情  
  
 ▫️ 适配Xray/Afrog/Nuclei检测脚本  
  
 ▫️ 支持内置与自定义POC目录混合扫描   
  
🔄 更新计划   
  
▫️ 每周新增7-10个实用POC（来源公开平台）   
  
▫️ 所有脚本经过基础测试，降低调试成本   
  
🎯 适用场景   
  
▫️ 企业漏洞自查 ▫️ 渗透测试 ▫️ 红蓝对抗   
▫️ 安全运维  
  
✧━━━━━━━━━━━━━━━━✧   
  
⚠️ 声明：仅限合法授权测试，严禁违规使用！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLGZQibsojRG3EA5F2iaF6A4Wo3e1ptB36kO5jf2xatEGw7UZx7N1S8AesaicZaMrYGDfH0OCG8GAE0g/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
