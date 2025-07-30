#  nginx-0.7.65_漏洞复现   
原创 剑豪321  网络安全学习爱好者   2024-11-12 18:49  
  
### Nginx简介  
  
Nginx(engine x) 是一个高性能的HTTP和反向代理web服务器，同时也提供了IMAP/POP3/SMTP服务。其将源代码以类BSD许可证的形式发布，因它的稳定性、丰富的功能集、简单的配置文件和低系统资源的消耗而闻名。2011年6月1日，nginx 1.0.4发布。  
  
Nginx是一款轻量级的Web服务器/反向代理服务器及电子邮件（IMAP/POP3）代理服务器，在BSD-like 协议下发行。  
  
其特点是占有内存少，并发能力强，事实上nginx的并发能力在同类型的网页服务器中表现较好，中国大陆使用nginx网站用户有：百度、京东、新浪、网易、腾讯、淘宝等。  
## 启动环境  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGAhNhQCLfbecRODRmjg3AKAOhonf8I1huyzgk6iaRIr34tpwwanQvianVa7xsVy5RjdAdq8Piaa3WzXA/640?wx_fmt=png&from=appmsg "")  
  
            2.     访问抓包修改文件后缀  
  
	  
可以显示phpinfo  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGAhNhQCLfbecRODRmjg3AKAx0xj24W6iaN6uvAvVwBDclxHGGBS5H7lqz6LQY4FmiaUg6fsltaFAicIg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGAhNhQCLfbecRODRmjg3AKAu73xtqrLGndaZxb3jicrLzZbbos8dJnbicwzIg5LsgKbpniaZmnrniav0A/640?wx_fmt=png&from=appmsg "")  
## Nginx 解析漏洞复现  
  
1.开启环境  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGAhNhQCLfbecRODRmjg3AKAXMM2NKib9nl2yfP2Sfw6rujVEYVO6IteMxD8iaxUiak7hppu30rIAJeNA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGAhNhQCLfbecRODRmjg3AKArHL9VbyTezuJTzDwhZEEm93NKDdgz9cNd33aEfAwgj5axEcm8fYtpw/640?wx_fmt=png&from=appmsg "")  
  
2.抓包修改文件后缀，类型以及内容头  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGAhNhQCLfbecRODRmjg3AKA9TJUSWeKkYrKuvEX72NNCYaDnKFmtEQypFbgHNoVCVNCYqW3LmqpFQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGAhNhQCLfbecRODRmjg3AKAS4vUMHE5sibmDtKaR5pZq0ue9Fdo8PiaYwLA4WibqTsNDHALFXeFUXKDw/640?wx_fmt=png&from=appmsg "")  
  
上传成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGAhNhQCLfbecRODRmjg3AKAY61Z0NUYM8WL00klebvEEHXdquXKdsWKCFoxOczQtLwHmgKrj5a7hw/640?wx_fmt=png&from=appmsg "")  
  
使用蚁剑连接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZAPxzic90CGAhNhQCLfbecRODRmjg3AKAMszgwYSiclclYx1Gx3TegQwI7WfORsrrHbmBM0LRl4KMKCkv1icia8bxw/640?wx_fmt=png&from=appmsg "")  
  
  
  
Nginx "文件名太长" 漏洞是由于Nginx在处理包含过长文件名的HTTP请求时，未正确处理内部缓冲区导致的。攻击者可以通过构造特殊的请求，使得Nginx在处理这些请求时因缓冲区溢出而崩溃，从而获得服务器的控制权。  
  
原理解释：  
  
Nginx在处理包含较长路径的请求时，会将这些路径存储在固定大小的缓冲区内。如果请求中的路径长度超过了Nginx为该缓冲区设置的最大长度，就会导致缓冲区溢出。这个溢出可能会导致Nginx服务崩溃，从而使得攻击者可以利用这个漏洞执行恶意代码或获取服务器的控制权。  
  
解决方法：  
  
1.升级Nginx到不含此漏洞的版本，建议升级到1.15.2或更高版本。  
  
2.如果无法升级，可以通过配置Nginx，限制请求行的大小，例如设置client_header_buffer_size和large_client_header_buffers指令来减少存储路径的缓冲区大小。  
  
3.应用安全补丁或更新。  
  
4.监控服务器日志，一旦发现异常，立即进行调查和响应。  
  
漏洞环境来自于vulhub，直接在vulhub下载即可！  
  
