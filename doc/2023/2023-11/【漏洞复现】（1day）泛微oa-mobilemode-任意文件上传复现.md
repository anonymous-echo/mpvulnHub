#  【漏洞复现】（1day）泛微oa-mobilemode-任意文件上传复现   
南极熊  WK安全   2023-11-25 14:57  
  
0x01 阅读须知  
  
**SCA御盾实验室的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
  
**0x02 漏洞描述**  
  
**（一）**  
**泛微oa**  
  
泛微OA拥有自主知识产权的协同管理软件系列产品，包括大中型企业使用的平台型产品e-cology，中小型企业使用的应用型产品e-office，以及一体化的移动办公云OA平台eteams。此外，泛微OA还发布了以“移动化、社交化、平台化、云端化”四化为核心的全新一代产品系列，帮助企业更好地对接移动互联。  
  
泛微OA不仅具备了成熟的内部运营管理和客户服务体系，更有一套完整的服务体系，涵盖咨询、方案、实施、培训、技术支持、版本升级等环节。其服务方式也多种多样，包括网站、邮件、电话、电子期刊、自助问答、企业知识库等。泛微OA遍布全国的服务网络，以及专业的咨询和服务人员，能够为客户提供更加便捷和高效的服务。  
  
**。**  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIjsGDSfjoqfUoZq9fX1dvte5iaUBYvo9L3PpMZptVZd89Cx87hx4Kx5xOlmuS6Q5vWH0SnZC5cyReA/640?wx_fmt=png&from=appmsg "")  
  
fofa语法：  
```
app="泛微-E-Weaver"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIjsGDSfjoqfUoZq9fX1dvte2SH7XdgCnBy6BiaXyzjCXGTn7rSbWHcXibz8wwz1NdsUGrQQeu44GUVg/640?wx_fmt=png&from=appmsg "")  
  
（二） 漏洞复现    
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIjsGDSfjoqfUoZq9fX1dvtepCb9HTlhz3800bJyA7OUg94iaee3G57mLzbdmo6dkP473ecdImWFDuw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RxxRc1KlrIjsGDSfjoqfUoZq9fX1dvtennPlnUOkricMproaxouXgenjaLl7rHaA4GvZv0MnRiajQEy6L7gWibgicA/640?wx_fmt=png&from=appmsg "")  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/S2ssjS1jNYvM6WiaR5ibLImBVXffTWBPcwFRclvucl2KDBy7oCHGic78sP8CjxYf2QtRQNAxgn0BjfaLSH0ruUlCw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
****  
