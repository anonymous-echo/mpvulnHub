#  Reporter内置报表管理系统敏感信息泄露+远程RCE漏洞   
NT-V  NightmareV   2024-03-08 07:00  
  
声明：  
  
请勿使用本文档提供的相关  
操作及工具  
开展任何违法犯罪活动  
。  
本技术类文档与工具仅支持学习安全技术使用，他用造成严重后果，请自行负责！！！  
  
一、  
漏洞名称  
  
Reporter内置报表管理系统敏感信息泄露+远程RCE漏洞  
  
二、  
漏洞概述  
  
Reporter内置报表管理系统存在敏感信息泄露+远程RCE漏洞，攻击者利用该漏洞可实现后台登录，并在服务端任意执行代码，写入后门，获取服务器权限，进而远程控制整个Web服务器。  
  
三、  
FOFA搜索语法  
  
body="Get_Verify_Info(hex_md5(user_string)."&&title=="Login @ Reporter"  
  
四、漏洞验证截图  
  
登录界面如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8Ja9o8GGxg9p3LUu2xfcKACgjSqyVwdN5l5PDgA6PNkicFJ45CfQQGWA/640?wx_fmt=png&from=appmsg "")  
  
访问登录界面，通过相关操作全局搜索  
“password”字段，可获取到后台登录账号和密码MD5加密值。通过解密，即可成功登录后台。具体如下图所示：  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8pic9fQAhQicR2pIPKKo6j97fFq1MbEA1yoGic9q2sBnX6zxY5cPb8iah9Q/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8j8iarzibqmZNbLRibhh1TictOFqrBcrVuNqiaaAZleynVkyBaMTzgZXlbYw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8Rsz1YBL1BJCAibvmJpibpXfYk6ndxKwrP18tCDhVE4ciaS5z7h4dHnkFA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8MOkoMXcCMH70SWj6Iy41M3z8MoIbA1QBObRNZm3ibHm8bOGBjwCOggA/640?wx_fmt=png&from=appmsg "")  
  
通过解密，可获取到密码明文内容。如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8LWEl0lvgYTcMd6qsbXbOvENsWVPwB8icPx11sHYxencF6dHQdK8glCw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8pkLAHBM4PXTibrkrdP2T6rz6Jt0ia8yVIZxesVaWT4PQKVV04tpCGGOw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8Z7G2E0HZWRz4zjcMPeKvSjapGXNlsV6ibpfJFk1zaQhBZMmOH7RFZpw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8bcffvefBWvAYeJUwkLtlZ4KTOicJkszanWACS2ff4T3D2qLiaCIU7fWw/640?wx_fmt=png&from=appmsg "")  
  
登录后台。如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8pSPrxTZuA6Wvrx3SMLSUfISGAjw69HVlOjIqzcDmpfdmhnWXmJZ8mQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8TjcOibJek9JEbpN0TgKv0qQsHSEHQDw88TFygMSwIcJTExSibnHe3PPA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8lcqQzWvPCnMZgj9Cic02Gc6tr5YYWQB8pwKE1mdw4QicUwIfCwnDeJ4Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8axHhQMkwlYwicMUbhJMaNPqtFVfQgPRn9hCqM7G1FxZfZ3qqtyUgscg/640?wx_fmt=png&from=appmsg "")  
  
通过  
RCE漏洞实现后门写入，并最终远程拿下Web服务器整体控制权。如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag87ibgdFPnJXO38fwKAAlE1WgGicic8jtcLOSbgW9ib25KM4beVGgar3ibjdw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8sz1f4rqwtVzYqExV1aQ6L3fgA7cicwSocHfPG8EtdmFUkurhJjxPWNw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag817fk9BTPRc5f2khQ9Qkib8LrjjJPO6upZvSNay0vrxkgqyEib0wvBRsQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8uczDH1kicRtCskAhSa4qfn3fLshWZMlc194ibBpNtxMoyS2xDGKgCcTA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8T1K4vIvsA0KfO1iasVBDicusb9XNiaicbjdPGPu7ickBIeWNX2rv2atiaobw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8uC8UvKhbcOOedHQk9axesAibSNibUsoiaWvOlnO24RyaANeTiahqzrpXMQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8Q3QPibGicpWWvGWKQd859uuRiciaVMT9eoPOX9ia4W9vibJm5cMnjojctwlA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8PYiaK0bZiaCAEdsS2HWoogt0icX1FrEtvjpJOWUR8Tz2W9WVquxWdL93A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8N5Yk3PpE3DBQzB5ibhlxTpibiaKcjjRSmde6hNibw25Gp9bPSvPbGO4wicg/640?wx_fmt=png&from=appmsg "")  
  
漏洞  
POC在下方知识星球内，扫描二维码，即可查看POC内容  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftnAJP4l5wFxxbGLxehCXag8vJLxy7QR18owZWrV7IhsSoV9fRC7gK2MUpZziaZFTWbicHfibjrZzh02w/640?wx_fmt=png&from=appmsg "")  
  
