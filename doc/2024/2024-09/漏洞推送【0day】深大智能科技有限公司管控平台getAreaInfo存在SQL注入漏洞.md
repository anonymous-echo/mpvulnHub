#  漏洞推送|【0day】深大智能科技有限公司管控平台getAreaInfo存在SQL注入漏洞   
 小白菜安全   2024-09-21 20:21  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞描述  
  
  
智游宝是连接景区与分销商(OTA、旅行社)的公正、权威、可信的第三方服务平台。作为国内智慧景区第三方技术服务支撑平台，智游宝为景区提供了可控制分销商的管理环境，安全、便捷、高效地实现了电子票的生产、发送、检票、退换票以及票款回收等技术环节；为分销商提供了便捷的采购和发货渠道；为景区提供了一系列数据分析报告，辅助景区决策。浙江深大智能科技有限公司管控平台服务端getAreaInfo存在sql注入漏洞。****  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
资产信息  
  
  
FOFA:  
body="ItemsControlServer.aspx"  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NhLcT1kxlia2TciaLw5yibtXk2PFHRp2c7N1Ctmy9SBXIDE8vdQnJFH5ibQEsbZvEjJU16gTn2S2FKxs2tBHiasQMGw/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2TciaLw5yibtXk2PFHRp2c7NRuZqYicKYburMuVuATzxYImbe7BTHEePNutLgtO0mJVY3kgHjLase1A/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
POC  
  
```
加入内部圈子获取
```  
  
  
---------------------------------------------------  
  
更多漏洞poc加入内部圈子获取，回复“优惠卷”，福利限时发放。  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgOaSVwdVAPT7DWSKK7pjSWGdbQKWEM0yTB3JSqNxLUnEBesOW8eG40w/640?wx_fmt=png&from=appmsg "")  
  
免责声明  
  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgAth2WTu4kyEzL1Dia7AXUWcP7tsbHDtpaH1cls1lJTPVNE6XTwLYvJg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
