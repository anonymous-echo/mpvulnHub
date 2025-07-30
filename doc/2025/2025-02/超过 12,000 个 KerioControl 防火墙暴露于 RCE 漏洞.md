#  超过 12,000 个 KerioControl 防火墙暴露于 RCE 漏洞   
Rhinoer  犀牛安全   2025-02-20 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlEq1M1v6OCBuknjZQcg1BdnGlGSgibsJwMsGljLxMN4eIaTcibWjvHUdvI0GvP16q2hvqwupU5OIOQ/640?wx_fmt=png&from=appmsg "")  
  
超过一万两千个 GFI KerioControl 防火墙实例存在严重的远程代码执行漏洞，漏洞编号为 CVE-2024-52875。  
  
KerioControl 是一款网络安全套件，可供中小型企业用于 VPN、带宽管理、报告和监控、流量过滤、AV 保护和入侵防御。  
  
该漏洞是安全研究员 Egidio Romano (EgiX) 于 12 月中旬发现的，他展示了危险的一键 RCE 攻击的可能性。  
  
GFI Software 于 2024 年 12 月 19 日发布了针对 9.4.5 Patch 1 版本问题的安全更新，但三周后，根据 Censys 的数据，仍有超过 23,800 个实例存在漏洞。  
  
上个月初，Greynoise 透露，它已经检测到利用 Romano 的概念验证 (PoC) 漏洞的主动攻击尝试，旨在窃取管理员 CSRF 令牌。  
  
尽管有关于主动利用的警告，但威胁监控服务 Shadowserver Foundation目前报告称，有 12,229 个 KerioControl 防火墙面临利用 CVE-2024-52875 的攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlEq1M1v6OCBuknjZQcg1BdqpP2WT3Vd2SOUFibliaJTzrog4EhsVYfHYrrwzHoHHlXBcWRoaD0Xq8g/640?wx_fmt=png&from=appmsg "")  
  
这些实例大多位于伊朗、美国、意大利、德国、俄罗斯、哈萨克斯坦、乌兹别克斯坦、法国、巴西和印度。  
  
由于 CVE-2024-52875 有一个公开的 PoC，因此利用的要求很低，甚至不熟练的黑客也可以加入恶意活动。  
  
Egidio Romano解释道：通过“ dest ”GET 参数传递给这些页面的用户输入在用于生成302 HTTP 响应中的“ Location ”HTTP 标头之前没有得到适当的清理” 。  
  
具体来说，该应用程序无法正确过滤/删除换行符 (LF)。这可能被利用来执行 HTTP 响应拆分攻击，进而可能允许执行反射型跨站点脚本 (XSS) 和可能的其他攻击。  
  
“注意：反射型 XSS 向量可能会被滥用来执行一键远程代码执行 (RCE) 攻击。”  
  
如果您尚未应用安全更新，强烈建议您安装 2025 年 1 月 31 日发布的 KerioControl版本 9.4.5 Patch 2，其中包含额外的安全增强功能。  
  
  
信息来源：BleepingComputer  
  
