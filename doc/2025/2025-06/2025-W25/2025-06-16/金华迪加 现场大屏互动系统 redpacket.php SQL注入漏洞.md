> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMTcwMTg1Mg==&mid=2247491829&idx=1&sn=f0e1ec63d977fad0aead47ea777d0182

#  金华迪加 现场大屏互动系统 redpacket.php SQL注入漏洞  
Superhero  Nday Poc   2025-06-16 02:54  
  
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
  
  
金华迪加 现场大屏互动系统 redpacket.php 接口处存在SQL注入漏洞，未授权的攻击者可通过此漏洞获取数据库权限，从而盗取用户数据，造成用户信息泄露。  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:  

```
body=&#34;/wall/themes/meepo/assets/images/defaultbg.jpg&#34; || title=&#34;现场活动大屏幕系统&#34;
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKVrVmuRyORFI0JlkSts0peZbxLOBNw0SBzEz3Pib7icRN6WNB0BiclLUoDfP7DeeiccicCVcAZ7vicB2iaw/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
延时4秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKVrVmuRyORFI0JlkSts0peiaibCZ603wTc7anBTr4pHl8yBibhJrPk2UicntLbic8K8QkeSlNibAM70Flg/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKVrVmuRyORFI0JlkSts0pemymCut78cSnIbdjT7icN8o7Pak61bOsAhcrQHNvH64zt0S56u6553eQ/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKVrVmuRyORFI0JlkSts0peYibE5ia75O8wV7IEvbEMsFvPe0UxqOA3pqRoJl5icC6lVJwQiaia5KFC4Sw/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKVrVmuRyORFI0JlkSts0peVpM6ibsr3iaRmojHEM3Dp0U6ZbXeKS7LzdibwWSS3Jtdm6xITh2YDnUzQ/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKVrVmuRyORFI0JlkSts0pehKDeq62ZnmicXbSicdqO9c33fAgT0dJMX88XxjyupMluL3l6BwCo4vGw/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
升级至安全版本  
  
  
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
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKVrVmuRyORFI0JlkSts0peiahuQ4D43Xu4pK7dYZoyRv0xgTMdtgCSugicwcibLNJ8Q6xF02a4BibdIg/640?wx_fmt=png&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
