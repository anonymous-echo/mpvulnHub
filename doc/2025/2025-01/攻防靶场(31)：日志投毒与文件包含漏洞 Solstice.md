#  攻防靶场(31)：日志投毒与文件包含漏洞 Solstice   
原创 罗锦海  OneMoreThink   2025-01-03 17:17  
  
目录  
  
1. 侦查  
  
    1.1 收集目标网络信息：IP地址  
  
    1.2 主动扫描：扫描IP地址段  
  
2. 初始访问  
  
    2.1 利用面向公众的应用  
  
3. 权限提升  
  
    3.1 利用漏洞提权：高权限运行的程序  
  
靶机下载地址：https://www.vulnhub.com/entry/sunset-solstice,499/  
## 1. 侦查  
### 1.1 收集目标网络信息：IP地址  
  
靶机启动后，没有提供IP地址。由于Kali和靶机在同一个C段，可以扫描ARP协议获取靶机IP地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG9mKkZnRpYaS9SX167icImxVYibyOCXu0GTXUzvG9g48Mn0DicPc0NibDxYw/640?wx_fmt=png&from=appmsg "")  
### 1.2 主动扫描：扫描IP地址段  
  
对靶机进行全端口扫描、服务扫描、版本扫描，发现：  
  
1、21/FTP、2121/FTP、62524/FTP  
  
2、80/HTTP、3128/HTTP、8593/HTTP、54787/HTTP  
  
3、22/SSH、25/SMTP、139/SMB、445/SMB  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG9ccqgMtPJEZCiciaHY4ZtTN8GA1EtWJvjdwoVhfqVr58hnhROCv97eCKw/640?wx_fmt=png&from=appmsg "")  
## 2. 初始访问  
### 2.1 利用面向公众的应用  
  
逐个检查各个端口是否存在漏洞，最终在8593/HTTP发现存在文件包含漏洞。  
  
但是通过包含配置文件，并未翻到有效凭据进行服务登录。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG9uA9UiaQpSz3o7S9POXTWcT4j7kY1oycsFOJKEKib9C26Uj1BF0cibN22A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG95hsVXFw1w1eZkCyx6v8yKooqeyL8HxDT9HM7dRT00QjbHLCwfjmlEA/640?wx_fmt=png&from=appmsg "")  
  
打算通过日志投毒向服务器写入webshell，再通过文件包含进行利用。  
  
逐个访问，确认ssh登录日志无法访问、smtp通信日志无法访问、http访问日志可以访问，那就通过http访问日志进行投毒。  
  
逐个访问，确认该http访问日志不是3128/HTTP、8593/HTTP、54787/HTTP产生的，是80/HTTP产生的，那就通过80端口进行投毒。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG96k9HcUzqAmQFxRLib6DTRapQMfx1jWSDlgaibvibl2ibypU3Ols6S7rfPQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG9iaweZfRdFXB4Ik2ZSuicB7V4s8X6EwCfeySzpf9C4oT1x2KmvLG39Pwg/640?wx_fmt=png&from=appmsg "")  
  
在请求头UA字段中添加webshell，使用蚁剑连接http访问日志，最终**获得www-data用户权限。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG9kaTya6PEP5ybXZLVAMjKTKcrYjvsMD6j56icVfIjMrdcsf4j8RzCcuw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG9Haq8ILIDqUGKttAickN7lVQ1dKBhZC4MCx4pEYzJQO3dUz1sg9nGKbg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG9uJbdl5bKVYj9Vzma8xpEC9thLaqq5v66ickGlT7xuB2qHDgWprBcUhA/640?wx_fmt=png&from=appmsg "")  
## 3. 权限提升  
### 3.1 利用漏洞提权：高权限运行的程序  
  
查看root用户启动的进程，发现root用户在本地回环地址的57端口上启动了web服务。  
  
如果能拿到这个web服务的webshell，那么获得的就是root用户权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG9IrMl4dOzQIsA6xatS4B2nFVHHQhc0L7hETDbOu84eFQRvokmfSq55w/640?wx_fmt=png&from=appmsg "")  
  
当前www-data用户在该web服务根目录中有写入权限，可以写入webshell文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG9h3jh414S0icX8xDx50TCTOX4VHYp6GMPLAtZcIVxP6MF7OIsMC364TQ/640?wx_fmt=png&from=appmsg "")  
  
写入反弹webshell，通过访问webshell文件触发执行，最终**获得root用户权限。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG9oIfCkDPDyUZRGB7RWVLHicj23icnuwG7VuxaIGDlX36nxcuayZm873CQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG9jPuJccPTChCUX50xcM11ZcDTibR7LTwGYRC8JeP0KrYAvYe6emvUibJw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hJB695EcV92LEpZ9h8VzUichXhCDSKzG9Sia6OpBLV0fMA2a62eIfiaztwib936aOj55Iw0IbxXYy7psbU887dnTpg/640?wx_fmt=png&from=appmsg "")  
  
  
