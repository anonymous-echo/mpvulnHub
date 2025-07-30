#  山石网科：关于网传WAF漏洞说明   
原创 优质可靠的  山石网科新视界   2024-08-22 23:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NGIAw2Z6vnKvXxzN9syadS6NM2YvjAFg2NBLDqDGZVP1U0V8gHOVwgkjJ2wpWTDz4YRA2t8rlEWdxNWIhnnhpA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**山石网科安全公告**  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
尊敬的用户：  
  
您好！  
  
  
近日，山石网科产品安全事件响应团队（PSIRT）接到了关于山石网科WAF产品潜在安全漏洞的报告。经过我司技术团队深入分析，确认此漏洞影响的版本范围为5.5R6-2.6.7至5.5R6-2.8.13。  
**该漏洞已在2022年8月发布的WAF 5.5R6-2.8.14版本中随新功能的引入得到修复**，5.5R6-2.8.14及后续版本均未受此漏洞影响。  
  
  
我们严格遵守《信息安全技术—网络安全漏洞管理规范》，在接到第三方的反馈后，迅速在官网上发布了相关安全公告，可扫码查看。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NGIAw2Z6vnL35e8Z4HYDiadicOo1GQTAgGzB1OBPdN5Q4rDBQlicb0TsI2KNuicdad5mn0UiaFWzsvsr3ts1RJrZbcQ/640?wx_fmt=png&from=appmsg "")  
  
  
**处理措施**  
  
  
针对可能受到该漏洞影响的客户，我们  
**推荐您将WAF升级至5.5R6-2.8.14或更高版本**。若短期内无法进行升级，我们建议通过“可信主机访问”的方式缓解风险，具体配置方法如下：  
  
- 登录WAF系统后，依次进入“系统”->“设备管理”->“可信主机”，点击“新建”；  
  
- 选择匹配类型为“IPv4”或“IPv4&MAC”；  
  
- 设置IP类型为“IP地址和掩码”，输入您的可信IP地址；  
  
- 选择登录类型为“HTTPS”。  
  
（ 若要删除预定义的可信主机，进入“系统”->“设备管理”->“可信主机”，选择“预定义”，找到“可信主机 0.0.0.0/0”，然后点击删除）  
  
我们深知网络安全的重要性，并承诺持续提供高质量的产品和服务。如果您在升级或配置过程中遇到任何问题，或需要进一步的技术支持，请随时联系我们的客服团队（  
服务热线：400-693-0555）。  
  
  
感谢您对山石网科产品的信任与支持，山石网科将继续为您的安全竭尽全力。  
  
  
此致  
  
敬礼！  
  
山石网科产品安全事件响应团队  
  
2024年8月22日  
  
  
注意：由于网络原因，上述公告页面可能暂时无法访问。请您检查网页链接的合法性，并在网络状况允许的情况下进行重试。若链接访问持续存在问题，请及时与我们联系获取进一步的帮助。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批科创板上市公司的身份，在2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请500多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及边界安全、云安全、数据安全、业务安全、内网安全、智能安全运营、安全服务、安全运维等八大类产品服务，50余个行业和场景的完整解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NGIAw2Z6vnIunOKIgoia7NibiaoWvRJIt9LFaW6icqVSicJzZqLlIicdic3LjTrIcsWc2D1GNia3YKcWWia53a0Z64X0u0A/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
