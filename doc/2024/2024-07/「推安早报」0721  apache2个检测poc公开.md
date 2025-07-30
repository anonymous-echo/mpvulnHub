#  「推安早报」0721 | apache2个检测poc公开   
bggsec  甲方安全建设   2024-07-21 09:47  
  

	#  2024-07-21 「红蓝热点」每天快人一步  

	>   
>   
> 
			1. 推送「新、热、赞」，帮部分人阅读提效
			2. 学有精读浅读深读，艺有会熟精绝化，觉知此事重躬行。推送只在浅读预览
			3. 机读为主，人工辅助，每日数万网站，10w推特速读
			4. 推送可能大众或小众，不代表本人偏好或认可
			5. 因渲染和外链原因，公众号甲方安全建设发送日报或日期,如20240721获取图文评论版pdf
		  
>   
  

	###  0x01 Apache HTTP服务器高危漏洞影响版本2.4.0至2.4.61  

	>   
> GitHub 上的一个仓库（TAM-K592/CVE-2024-40725-CVE-2024-40898）披露了两个高危漏洞（CVE-2024-40725 和 CVE-2024-40898），这些漏洞影响了 Apache HTTP Server 2.4.0 至 2.4.61 版本，可能导致源代码泄露和服务器端请求伪造（SSRF）攻击。
		  
>   
  
  

	  

	
	![](https://mmbiz.qpic.cn/sz_mmbiz_png/icqm3vRUymZn2p6s1XVfMoaQYTCUPYkXJ2MuCAeQfbKdic0wwpibVtYazBFzeLxBqiaQKC2moy7gWbYzfBhlxdDOkQ/640?from=appmsg "")  

	  


	###  热评   
- Apache HTTP Server 2.4.0 - 2.4.61 版本存在漏洞 CVE-2024-40725 和 CVE-2024-40898  
  
- Apache HTTP Server 2.4.0-2.4.61 版本发现漏洞 CVE-2024-40725 和 CVE-2024-40898  
  

	  

		
	  

	###  关键信息点   
- CVE-2024-40725 漏洞的存在是由于 mod_proxy 模块在处理 ProxyPass 指令和 URL 重写规则时的解析不一致，这可能导致 HTTP 请求欺骗攻击。  
  
- 攻击者可以通过发送精心构造的 HTTP 请求来利用这个漏洞，从而在代理服务器和后端服务器之间造成请求解析的不一致，进而实现信息泄露等攻击。  
  
- CVE-2024-40898 漏洞的危险之处在于，它允许攻击者绕过 mod_ssl 模块的客户端认证机制，这可能导致未授权的系统访问。  
  
- 对于这两个漏洞，最重要的缓解措施是升级到 Apache HTTP Server 的最新版本，同时对现有的代理和 SSL 配置进行审计和加固，以确保不会因为配置错误而暴露于这些高危漏洞。  
  

	
	  
🏷️: CVE, SSRF, 漏洞, Apache HTTP服务器, HTTP请求走私  
  
  

	  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icqm3vRUymZlbmEWU7ZApsl3ia3YLicI4H3nwksKq8ZBqrghjtia9TYiblaxU2VXrUpDcAM57Ric0wX9pBg69IusWVyg/640?wx_fmt=jpeg "")  

	  

		快来和老司机们一起学习吧  
  
