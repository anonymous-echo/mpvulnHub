#  安美酒店管理系统/get_user_enrollment.php接口 sql注入漏洞   
Superhero  Nday Poc   2025-04-16 01:59  
  
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
  
  
安美酒店管理系统  
/get_user_enrollment.php接口存在SQL注入漏洞，未经身份验证的攻击者通过漏洞执行任意SQL语句，调用xpcmdshell写入后门文件，执行任意代码，从而获取到服务器权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
title="酒店宽带运营系统"
```  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKXGzWrzpYOQPnsgSG8UicUZ3Qic42H0EyXLLoaTxcnYEqLMiaJJOqAINOE6DO1MdZS05TvhmtIQNAPg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**03******  
  
**漏洞复现**  
  
延时4秒，执行2次  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKVYVhOdic0Acm1PX1mmvVWlHfSJTuVKutqKUkb5ncg7RbibWFo5XfVGliauDocT34WcMJ6hprscmUYw/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKVYVhOdic0Acm1PX1mmvVWlw2uAcIUSbJJS9mBvxDOFtHRm6cFOWJE6saFXaLBbZ0FEe91lyXnpIg/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKVYVhOdic0Acm1PX1mmvVWlN8jGowe5Bk6D9ricruottZsic0p1EvF0s5WscqBqOB539xa4PGibibpQ8w/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKVYVhOdic0Acm1PX1mmvVWlZwicIhv1nm7zsEuHt5QrjrRAzR9iar7JzScRiapf2pUibGWAOibiaLmCkibkw/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、关注厂商官网，及时升级至安全版本或更新安全补丁  
  
  
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
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0beBCCyKGykkAazuPyvibgC0ooBGy9elQQ72f1WIB73UDYuPhx8cnCobvnOBdTcxmdwBbt2eAYIQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
