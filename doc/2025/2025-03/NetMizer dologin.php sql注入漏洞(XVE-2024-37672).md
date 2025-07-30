#  NetMizer dologin.php sql注入漏洞(XVE-2024-37672)   
Superhero  Nday Poc   2025-03-29 21:23  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号Nday Poc及作者不为此承担任何责任，一旦造成后果请自行承担！  
  
  
**00******  
  
**产品简介**  
  
  
NetMizer日志管理系统  
是一款专为网络流量管理和优化设计的日志记录与分析工具，能够高效采集、存储和分析网络设备及应用的日志数据。系统提供实时监控、异常检测、日志查询和可视化报表功能，帮助管理员快速定位网络问题，优化性能，并满足合规性要求。其强大的搜索和过滤功能，结合自动化告警机制，确保网络运行的稳定性和安全性，适用于各类企业和数据中心环境。  
**01******  
  
**漏洞概述**  
  
  
NetMizer 在/dologin.php接口存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
app="NetMizer-日志管理系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXmUib8KoZvgDG2xOt4Kw952xYRu2ge00uHwliaIqkcAcLYexez1sg1sPAg/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
延时8秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXmspWbZELWFLspu5iaNjXKmp1QiaWZzSmVSKq36sLdqtXCLEkAU8RaKsBw/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXmp4ptjogyFa47LAmjDTHelJb0E6aRHXYSkY1Ad9NJbNrEJzboa1aGHg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXmZNsXmGSWibtW3P1uHKhcU9CSrP7jt5ibFk3MW8JzRjjCEKmzPlLbmgTA/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXmEcibeyQiaIQhp1o36zr6k2ibkP8Txj82EOIcS9yRpBnhQRTBiaCtdWRXyw/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXmy87VUKSrEuCglszQOw3zUp0L2n25J6PK5PzyNDJdkicouaRRPH1clnA/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
下载官方补丁进行修复  
  
  
**06******  
  
**内部圈子介绍**  
  
  
【Nday漏洞实战圈】🛠️   
  
专注公开1day/Nday漏洞复现  
 · 工具链适配支持  
  
 ✧━━━━━━━━━━━━━━━━✧   
  
🔍 资源内容  
  
 ▫️ 整合全网公开Nday漏洞POC详情  
  
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
  
  
