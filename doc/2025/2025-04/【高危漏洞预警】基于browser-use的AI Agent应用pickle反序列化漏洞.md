#  【高危漏洞预警】基于browser-use的AI Agent应用pickle反序列化漏洞   
cexlife  飓风网络安全   2025-04-28 13:20  
  
漏洞描述:  
  
browser-use WebUI是基于browser-use的AI Agent应用,2025年4月,互联网上披露其旧版接口update_ui_from_config存在一个pickle反序列化漏洞,未经授权的远程攻击者可以利用该接口发送恶意的序列化数据,实现在服务端执行任意代码,导致服务器失陷。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00udJMoHJIbjDCFBibpe8w9hWdKTgXbicT8hOQYG0iaNwRGOzSAicjxbut3L32d2eX9QDnhBtVOibl6VnQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00udJMoHJIbjDCFBibpe8w9h2UZWibpc8cuJrU24Zq1icYLfuyC1kJrmc9pHWkhvDD3MVZaazybvEfsw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00udJMoHJIbjDCFBibpe8w9hNxmn8oOZAc6WGqOczo5qv8oFyGV46CGytlUMO9ovGYjAmBobCGWgYQ/640?wx_fmt=png&from=appmsg "")  
  
修复建议:  
  
升级至最新版本  
  
参考链接:  
  
https://github.com/browser-use/web-ui/commit/7fdf95edaeaf2505b36c10966b7b8d65359f1de6 	  
  
  
  
