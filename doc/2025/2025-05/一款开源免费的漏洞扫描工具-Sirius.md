#  一款开源免费的漏洞扫描工具-Sirius   
 黑白之道   2025-05-28 02:06  
  
> 在前面的文章中，提到过很多安全工具漏洞扫描工具，如Nessus等。但是很多工具都是收费的，本文为大家推荐一款开源免费的漏洞扫描工具Sirius Scan，  
  
  
Sirius Scan首个真正开源的通用漏洞扫描器，利用信息安全社区的集体智慧，超越商业产品。框架涵盖四大识别概念：漏洞数据库、网络扫描、代理发现和自定义评估分析。本文让我们一起来学习他的使用吧！  
# 安装  
  
安装建议使用Docker安装，执行命令如下：  
```
git clone https://github.com/SiriusScan/Sirius.git
cd Sirius
docker compose up -d

```  
  
安装完成后， 在浏览器中打开http://localhost:3000  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatj3nBeMqHRF8N2XlH0Fba5mjt4n6RcjStwYljULK2K3mgjIUXSUzABkGQfsRylZho3UjEOZzA10ug/640?wx_fmt=png&from=appmsg "")  
  
初始用户名和密码：admin  
：password  
# 功能描述  
  
**控制面板:**  
 展示系统运行状况指标、实时扫描活动和进度 最新的漏洞发现和趋势等。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Xb3L3wnAiatj3nBeMqHRF8N2XlH0Fba5mpdbbMLFP6nfJPbBdPs9CmJjdPIG2uMAJ8nMFibBPNk0mx3pfkGSXKag/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞扫描：**  
 输入目标地址，一键开始扫描。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatj3nBeMqHRF8N2XlH0Fba5mz1cCKjPsjxPPBMxDib59ARndtAU6U3xpEHLNWcTR7f1VgW8Ee0bLIEg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞查看：**  
 当扫描到漏洞后，我们可以在漏洞详情页面查看扫描结果，并提供了多种查看、排序和分析漏洞的方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatj3nBeMqHRF8N2XlH0Fba5mdibBtVv81z95KXj2rTBEhvlSuhGCBLBnfnaZDZK9lJ3C2MfZvVHQ37Q/640?wx_fmt=png&from=appmsg "")  
  
**漏洞报告：**  
 选择对应漏洞，会出现相关漏洞报告。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatj3nBeMqHRF8N2XlH0Fba5mFwj5Lm1ILXpV3LBawaBWrUuicX0bfIRmFDOIsPiclI5n2FibFGDInet9w/640?wx_fmt=png&from=appmsg "")  
# 总结  
  
Sirius  
是一款非常容易上手的安全扫描工具，对初学用户非常友好。感兴趣的小伙伴可以在Docker中直接部署吧！官网地址：https://sirius.publickey.io  
  
更多精彩文章 欢迎关注我们  
  
  
  
