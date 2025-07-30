#  Z0SCAN一款基于Python3的主、被动扫描器|漏洞探测   
工具-Cavin小编  渗透安全HackTwo   2025-02-13 16:01  
  
0x01 工具介绍 Z0SCAN是一个基于Python3的主、被动扫描器，旨在进行Web应用安全测试。它支持多种插件，包括SQL注入、XSS、文件上传、目录遍历等漏洞检测，并提供主动和被动扫描方式。Z0SCAN还包含一个MITM代理，用于拦截和分析HTTP/HTTPS请求。用户可以通过命令行指定扫描目标和配置选项，支持代理、超时设置、插件启用/禁用等功能。该项目采用GPL-2.0开源许可，适用于合法授权的企业安全评估。注意：现在只对常读和星标的公众号才展示大图推送，建议大家把渗透安全HackTwo"设为星标⭐️"否则可能就看不到了啦！  
**下载地址在末尾**  
  
0x02 功能简介插件列表PerServer插件名称插件简述检测方式要求IisShortnameIIS短文件名漏洞检测主动/IisNginxParseIIS与Nginx服务解析漏洞主动/ErrorPage错误页敏感信息泄露主动/OSSBucketTakeoverOSS储存桶接管主动/OSSFileUploadOSS储存桶任意文件上传主动/NetXSS.NET通杀XSS主动Level==4,NoWafNginxCRLFNginx服务CRLF注入主动/NginxWebcacheNginx错误配置-缓存清除主动/SwfFilesFlash通杀XSS主动Level==4,NoWafNginxVariableLeakageNginx错误配置-变量读取主动/IdeaIdea目录解析主动Level>=2BackupDomain基于域名的备份文件检测主动/PerFile插件名称插件简述检测方式要求SQLiBoolSQL布尔盲注检测主动NoWafSQLiTimeSQL时间盲注检测主动NoWafSQLiErrorSQL报错注入检测主动/CommandAspCodeAsp代码执行主动Nowaf,Level>=3CommandPhpCodePhp代码执行主动NoWaf,Level>=3SSTISSTI注入检测主动NowafXSS基于JS语义化XSS发现被动/AnalyzeParameter反序列参数分析被动/JsSensitiveContentJs敏感信息泄露被动/CommandSystem系统命令执行主动NoWaf,Level>=3DirectoryTraversal路径穿越主动NoWafUnauth未授权访问主动/PhpRealPathPhp真实目录发现主动/PerFolder插件名称插件简述检测方式要求BackupFolder备份文件扫描主动Level>=2DirectoryBrowse目录遍历主动/PhpinfoCrawPhpinfo文件发现主动Level>=2RepositoryLeak仓库源码泄漏主动NoWaf,Level>=2注意：插件的运行同时还会受到服务指纹的影响（忽略指纹要素的功能还在开发）0x04 更新介绍暂无0x04 使用介绍使用用法: z0scan [选项]选项：  -h, --help            显示此帮助信息并退出  -v, --version         显示程序的版本号并退出  --debug               显示程序的异常信息  -l {1,2,3,4}, --level {1,2,3,4}                        设置扫描级别，使用不同的payload：1-4（默认级别见config.py）代理：  被动代理模式选项  -s SERVER_ADDR, --server-addr SERVER_ADDR                        服务器地址格式：（ip:port）目标：  必须提供目标信息  -u URL, --url URL     目标URL（例如：“http://www.site.com/vuln.php?id=1”）  -f URL_FILE, --file URL_FILE                        扫描文本文件中列出的多个目标请求：  网络请求选项  -p PROXY, --proxy PROXY                        使用代理连接目标URL，支持 http, https, socks5, socks4，例：http@127.0.0.1:8080 或 socks5@127.0.0.1:1080  --timeout TIMEOUT     连接超时时间（单位：秒，默认为config.py中的设置）  --retry RETRY         超时重试次数（默认为config.py中的设置）  --random-agent        随机选择 HTTP User-Agent 头部值输出：  输出选项  --html                如果选中，输出将保存到输出目录（默认情况下），或可以指定路径  --json JSON           默认情况下生成 JSON 文件，保存在输出目录，你可以更改路径优化：  优化选项  -t THREADS, --threads THREADS                        最大并发网络请求数（默认为config.py中的设置）  --disable DISABLE [DISABLE ...]                        禁用某些插件（例如：--disable xss webpack）  --able ABLE [ABLE ...]                        启用某些模块（例如：--enable xss webpack）  --ignore-waf          忽略WAF检测主动扫描：被动扫描：  
0x05 内部星球VIP介绍-V1.4（福利）        如果你想学习更多渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点欢迎加入我们内部星球可获得内部工具字典和享受内部资源，每1-2天更新1day/0day漏洞刷分上分(2025POC更新至3500+)，包含网上一些付费工具及BurpSuite自动化漏洞探测插件，AI代审工具等等。Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复" 星球 "有优惠券名额有限先到先得！全网资源最新最丰富！（已有1500多位师傅加入，价格随人数进行上涨早加入早享受）  
**👉**[点击了解加入-->>内部VIP知‍识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新](https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247490028&idx=2&sn=f8ab9ff63625a96061ac28bed957dff0&scene=21#wechat_redirect)  
  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250214获取下载地址**  
  
# 最后必看  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4星球介绍(0day推送)**  
  
**2. 最新Nessus2024.10.7版本主机漏洞扫描下载**  
  
**3. 最新BurpSuite2024.7.3专业版中英文版下载**  
  
[4. 最新xray1.9.11高级版下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483882&idx=1&sn=e1bf597eb73ee7881ae132cc99ac0c8e&chksm=cf16a75af8612e4c73eda9f52218ccfc6de72725eb37aff59e181435de095b71e653b446c521&scene=21#wechat_redirect)  
  
  
[5. 最新HCL AppScan Standard 10.2.128273破解版下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发支持一下  
  
  
