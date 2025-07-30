> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMTcwMTg1Mg==&mid=2247491878&idx=1&sn=b19405b171f8932d27c8f7da700755cc

#  用友U8 GRP obr_zdybxd_check.jsp SQL注入漏洞  
Superhero  Nday Poc   2025-06-21 08:54  
  
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
  
  
用友 U8   
GRP obr_zdybxd_check.jsp  
 接口存在SQL注入漏洞，未经身份验证的攻击者通过漏洞执行任意SQL语句，调用xpcmdshell写入后门文件，执行任意代码，从而获取到服务器权限。  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:  

```
app=&#34;用友-GRP-U8&#34;
```

  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKJtxMwdqYqDk4jCibuHCibS5ZTDHSrBHJAUnYv3zTwib3gRTGjQkunIIKWib9moNG8A2M5QyNXe0e6iaQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
**03******  
  
**漏洞复现**  
  
延时4秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK3wU73qcvddP6IAdpDjefSF1b5ialLtm93LC3wnFjCicpt44mfrib89eo9XPgJgoRbfNlVk280E29Kw/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK3wU73qcvddP6IAdpDjefST6LMNEmCYZeTKTnroXQxib00j3JT6dIZRZmP9Dtm9hMssedxfAkwfdQ/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK3wU73qcvddP6IAdpDjefS3clnXCl3Qx0Bfqxm7EEJ9s354T7wNIgpVeOm9qqc9iaIk5dibYPK339A/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK3wU73qcvddP6IAdpDjefSOZWx0dqMEGKM2WmEbqW7x1D8RY9wMcmO3hDc3hibxejsWWo5ymcz9dg/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwK3wU73qcvddP6IAdpDjefSZL6UgokaztJr1L2ibD5icFHzAE5qhQgmZ9OQaegicweKFK7TdAfh9Bbmg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKJtxMwdqYqDk4jCibuHCibS51dmdjQ4On0lUspDKYcGf3vQiaUtt5r7DNQdRJHoiaQiakCJMdSLR2zMqw/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
