> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyMjM5NDM3NQ==&mid=2247486611&idx=1&sn=8adc678b9e846b06ef4a14bb516c8397

#  PHP代码审计登陆框SQL注入  
原创 学员投稿  进击安全   2025-07-22 04:25  
  
免责申明  
  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
一、漏洞分析  
  
位置：  
login.php  
  
![图形用户界面, 文本, 应用程序, 电子邮件

AI 生成的内容可能不正确。](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVdRowbXIaJlhnNibLsnhiaAYA9muB1KTCBKm8fv3rSwiak5ejibQTa20gxL7GsdKB9U5dv8NXfwiaNic5g/640?wx_fmt=png&from=appmsg "")  
  
代码第  
5  
行到第  
10  
行中，第六行通过  
post  
传递过来的  
voter  
参数，没做任何过滤，直接拼接到了  
sql  
中，并执行  
SQL  
查询。  
  
二、漏洞复现：  
  
访问漏洞  
URL  
：  
http://127.0.0.1/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVdRowbXIaJlhnNibLsnhiaAYFEJjFfooad76VmhiaoIAQsw4EFN4G0jzWyjaOEzllkOLSCt53LicYxmg/640?wx_fmt=png&from=appmsg "")  
  
  
输入任意数据后抓取数据包  
  
![图形用户界面, 文本, 应用程序, 电子邮件

AI 生成的内容可能不正确。](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVdRowbXIaJlhnNibLsnhiaAY11nicYLGibbjmNQ0q7HOhBZ4q7X2Zjp4r8hPrus4PV8lVZbwY00cl2xQ/640?wx_fmt=png&from=appmsg "")  
  
  
使用  
sqlmap  
进行测试  
  
Sqlmap  
具体命令：  
  
python sqlmap.py -r 1.txt --batch --current-db --dbms=mysql  
  
![文本

AI 生成的内容可能不正确。](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVdRowbXIaJlhnNibLsnhiaAYKWyFsCsM2QEOGroeEgb9aUMVNibOVLSgjKWKXGoJYoLKiboDiba7WoD3w/640?wx_fmt=png&from=appmsg "")  
  
  
![文本

AI 生成的内容可能不正确。](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVdRowbXIaJlhnNibLsnhiaAYPGUz25hf2fIXzzsgbGkp76QF4YCibT0a6YlLa7ujgDGCSXbPOdQSqMA/640?wx_fmt=png&from=appmsg "")  
  
  
得到当前数据库名  
: votesystem  
  
  
三、完结  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
  
