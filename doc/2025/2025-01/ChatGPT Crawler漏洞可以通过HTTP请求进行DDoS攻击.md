#  ChatGPT Crawler漏洞可以通过HTTP请求进行DDoS攻击   
HackSee安全团队  HackSee   2025-01-23 09:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/M8pOVgDSPVKKCCyw3uf65LEZic3fI39SD84IQCD4rsia20xNxU1OibrLuEZpFc8kU3m6dEAn1vvUYBTZp9biauLtpA/640?wx_fmt=jpeg&from=appmsg "")  
  
ChatGPT的网络爬虫的行为可以通过发现的漏洞来利用：在特定的查询条件下，OpenAI的bot可能会无意中对任意网站执行DDoS攻击。这个有趣的漏洞是由网络安全研究员Benjamin Flesch报告的。根据他的说法，对ChatGPT API的单个HTTP请求可能会引发针对特定web资源的无情网络请求的洪水。  
  
虽然这种DDoS攻击的规模可能不足以使保护良好的网站瘫痪，但研究人员仍然认为这是OpenAI的一个重大疏忽。例如，ChatGPT爬虫可能会为每个API查询每秒生成20到5000甚至更多的请求到同一个网站。  
  
“ChatGPT API在处理对https://chatgpt.com/backend-api/attributions的HTTP POST请求时显示出严重的质量缺陷。API期望在参数url中有一个超链接列表。众所周知，指向同一个网站的超链接可以用许多不同的方式编写。由于糟糕的编程实践，OpenAI不会检查指向同一资源的超链接是否多次出现在列表中。OpenAI也没有强制限制存储在url参数中的超链接的最大数量，因此可以在单个HTTP请求中传输数千个超链接，”Flesch解释说。  
  
不幸的是，网络爬虫不会检查指向同一域的重复链接，也不会对URL参数中的超链接的最大数量施加限制。当这个漏洞被利用时，受影响的网站所有者会从ChatGPT的爬虫中观察到流量。即使这些地址被防火墙屏蔽了，爬虫仍然会无情地发送请求。  
  
截至2025年1月10日（星期五），尽管通过官方法律渠道进行了大量报道，但OpenAI或微软仍未解决这一软件缺陷，两家公司都未承认其存在。  
  
  
  
