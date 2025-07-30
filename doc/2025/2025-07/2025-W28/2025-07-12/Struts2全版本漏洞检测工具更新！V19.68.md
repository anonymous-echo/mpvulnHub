> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650611404&idx=4&sn=f4ff1d606e1d6f8ff505f82837b16d16

#  Struts2全版本漏洞检测工具更新！V19.68  
 黑白之道   2025-07-12 14:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
## 工具介绍  
  
Struts2全版本漏洞检测工具 by:ABC_123  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2V4qLgKdCT8wyMrZtPqLexS0N0zl5icLWdK9jYOaH4QFjz1oJCGhMMMvsmiasRcIibJn6vLL5Lz4MJ2g/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
1、点击“检测漏洞”，会自动检测该URL是否存在S2-001、S2-005、S2-009、S2-013、S2-016、S2-019、S2-020/021、S2-032、S2-037、DevMode、S2-045/046、S2-052、S2-048、S2-053、S2-057、S2-061、S2相关log4j2十余种漏洞。  
  
2、“批量验证”，（为防止批量geshell，此功能已经删除，并不再开发）。  
  
3、S2-020、S2-021仅提供漏洞扫描功能，因漏洞利用exp很大几率造成网站访问异常，本程序暂不提供。  
  
4、对于需要登录的页面，请勾选“设置全局Cookie值”，并填好相应的Cookie，程序每次发包都会带上Cookie。  
  
5、作者对不同的struts2漏洞测试语句做了大量修改，执行命令、上传功能已经能通用。  
  
6、支持GET、POST、UPLOAD三种请求方法，您可以自由选择。（UPLOAD为Multi-Part方式提交）  
  
7、部分漏洞测试支持UTF-8、GB2312、GBK编码转换。  
  
8、每次操作都启用一个线程，防止界面卡死。  
## 更新  
  
2025.07.05 新增检测Struts2框架下Log4j2漏洞的新语句。  
  
2025.07.04 新增下载文件到指定目录功能，应对上传webshell过程无法绕过WAF的情况。  
  
2025.07.04 新增延时方法判断Struts2漏洞，解决Struts2框架无回显情况下的漏洞检测。  
  
2025.07.02 新增S2-018漏洞检测方法。  
  
2025.07.02 新增S2-017漏洞新的检测语句，进一步提升漏洞检测的准确度。  
  
2025.07.02 新增S2-019漏洞新的检测语句，进一步提升漏洞检测的准确度。  
  
## 工具获取  
  
  
  
https://github.com/abc123info/Struts2VulsScanTools/releases/tag/v19.68  
  
  
> **文章来源：夜组安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
