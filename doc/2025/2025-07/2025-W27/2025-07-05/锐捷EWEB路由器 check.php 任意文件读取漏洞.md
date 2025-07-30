> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMTcwMTg1Mg==&mid=2247492021&idx=1&sn=a7e4f43c8a2f6556f98aefe8b21fd3bb

#  锐捷EWEB路由器 check.php 任意文件读取漏洞  
Superhero  Nday Poc   2025-07-05 01:48  
  
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
  
  
锐捷EWEB路由器 check.php 任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:  

```
title=&#34;锐捷网络-EWEB网管系统&#34;
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJGSgPia1vPJrlFM7K55ibZ1usk91wMTfXZAWCLNnIBXWSANXFVDeibqgUjwsztK7cUUr46CmQbdQKtQ/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
1、获取可用cookie  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJGSgPia1vPJrlFM7K55ibZ1uQadopgERIaTFEp0YCunGn5c8k4gk21wGzcj9BClGCmF7czvJ49iatkA/640?wx_fmt=png&from=appmsg "")  
  
2、利用可用cookie读取文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJGSgPia1vPJrlFM7K55ibZ1usS5MyiaJhpfjK1g9ua7FzlYS4vv2mL2Liap0yZknjNJSxQ6rWND7nLdA/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJGSgPia1vPJrlFM7K55ibZ1u5ZTbdz7cyicf8jsDM9PUhJlgzkBBZDLarthDhlOqLjjpTj7PSt9OgdA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJGSgPia1vPJrlFM7K55ibZ1uccguf5iclicXJ5lPsFzVaygRY1pZxqzbT7Y9EjEkHbCbvEzdgnLr0J7w/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwJGSgPia1vPJrlFM7K55ibZ1ulxSozpvSumXB8Sw5eBCcXhYJsuszWibMR6I7OKs9MJpm3ZudyqibByxA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwL0IhuZBhAUQUAM6jESCvAneFtsibkxjUjmlq23IJNV84GljSiar5S6uh0OdeRIl7CyN8ecFFHiciaia5g/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
