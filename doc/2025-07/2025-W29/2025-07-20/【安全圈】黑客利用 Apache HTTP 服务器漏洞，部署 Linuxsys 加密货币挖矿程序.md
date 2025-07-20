> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070725&idx=3&sn=0ed096ca126a498dcb6caff13372e355

#  【安全圈】黑客利用 Apache HTTP 服务器漏洞，部署 Linuxsys 加密货币挖矿程序  
 安全圈   2025-07-19 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
### 1️⃣ Linuxsys 隐秘挖矿再现，利用 Apache 漏洞展开攻击  
###   
### 近期，“VulnCheck”发布报告揭示：攻击者正利用已知 Apache HTTP Server 2.4.49 中的路径遍历漏洞（CVE‑2021‑41773, CVSS 7.5）传播名为 Linuxsys 的加密货币挖矿程序。  
###   
- **感染链揭秘**  
：源自印度尼西亚 IP 
```
103.193.177.152
```

  
，攻击者利用 cURL 或 wget，从 
```
repositorylinux[.]org
```

  
 下载 shell 脚本，后续又从多处被入侵的正规站点获取 Linuxsys 挖矿文件。  
  
- **隐蔽传播机制**  
：通过合法站点中 HTTPS（有效 SSL 证书）的信任链隐藏下载来源，同时 cron 脚本确保挖矿程序重启自启动。  
  
- **多漏洞联合利用**  
：攻击者还曾借助 GeoServer、Confluence、Metabase、Palo Alto 等产品中的 n‑day 漏洞传播 Linuxsys，显示其基于长期采用已知漏洞，分布式传播的作战风格。  
  
### 2️⃣ GhostContainer Exchange 后门曝光：APT 攻入邮件核心  
  
  
同时，**Kaspersky GReAT**  
 团队披露在亚洲地区多家政府与高科技机构中检测到 Exchange Server 后门 **GhostContainer**  
，疑似利用已修补漏洞 CVE‑2020‑0688（CVE score 8.8）部署。  
  
- **隐蔽模式运行**  
：后门以 DLL 形式注入 Exchange Server，伪装为正常组件，执行 shellcode、文件操作、.NET 模块下载、网络代理与隧道功能。  
  
- **控制方式极隐秘**  
：GhostContainer 不主动联接 C2，而是监听通过 Exchange Web 请求中的隐藏数据，隐藏其存在，避免被普通 IDS/网络检测捕捉。  
  
- **APT 背景显现**  
：此次攻击针对亚洲特定目标，展现攻击者精于使用公开代码构建高级持久后门（APT），具有长期渗透与横向活动能力。  
  
##   
## 🔐 防御建议：构筑深度网络防护体系  
<table><thead><tr><th><section style="margin-top: 0px;margin-bottom: 0px;line-height: 1.5em;"><span leaf="">防护层面</span></section></th><th><section style="margin-top: 0px;margin-bottom: 0px;line-height: 1.5em;"><span leaf="">建议措施</span></section></th></tr></thead><tbody><tr><td><strong data-start="1063" data-end="1071"><span leaf="">漏洞修补</span></strong></td><td><section style="margin-top: 0px;margin-bottom: 0px;line-height: 1.5em;"><span leaf="">Apache 升级至 ≥2.4.51；立即安装 Exchange CVE‑2020‑0688 修复补丁。</span></section></td></tr><tr><td><strong data-start="1136" data-end="1144"><span leaf="">访问隔离</span></strong></td><td><section style="margin-top: 0px;margin-bottom: 0px;line-height: 1.5em;"><span leaf="">强制网络分段，确保服务器不直接面向 Internet；禁用不必要模块（如 mod_cgi）。</span></section></td></tr><tr><td><strong data-start="1203" data-end="1211"><span leaf="">日志监控</span></strong></td><td><section style="margin-top: 0px;margin-bottom: 0px;line-height: 1.5em;"><span leaf="">启用 IDS/WAF 机制，监控异常 HTTP/HTTPS 请求、shell 脚本、cron 文件增量。</span></section></td></tr><tr><td><strong data-start="1276" data-end="1284"><span leaf="">行为审计</span></strong></td><td><section style="margin-top: 0px;margin-bottom: 0px;line-height: 1.5em;"><span leaf="">部署 EDR/UEBA，识别挖矿、横向移动、命令注入特征及隐藏 DLL 文件活动。</span></section></td></tr><tr><td><strong data-start="1338" data-end="1346"><span leaf="">安全训练</span></strong></td><td><section style="margin-top: 0px;margin-bottom: 0px;line-height: 1.5em;"><span leaf="">员工培训识别钓鱼攻击、及时更新系统补丁，提升安全意识与应急能力。</span></section></td></tr></tbody></table>## ✅ 结束语  
##   
## Linuxsys 与 GhostContainer 是两条完全不同但隐蔽性都极强的攻击链：  
- 一条利用服务器端漏洞植入持续挖矿隐患；  
  
- 一条潜伏于 Exchange 核心，实现 APT 渗透与持续控制。  
  
此次案例再次提醒所有组织：**零信任+补丁管理+行为监控**  
是有效抵御此类高级威胁的核心策略。如果你需定制化检测规则或演练服务，欢迎后台联系支持沟通。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】制造业安全警报：为何必须彻底废除默认密码？](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070714&idx=1&sn=ccd1231536a99cc8c6648c5aaf2470c1&scene=21#wechat_redirect)  
  
  
  
[【安全圈】美政府用的“Signal 替代品”TeleMessage SGNL 爆出严重漏洞，堆内存泄露已被黑客利用](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070714&idx=2&sn=49209de3fb35fbb8e54342a5c92305c5&scene=21#wechat_redirect)  
  
  
  
[【安全圈】230万次下载面临威胁：LaRecipe漏洞可能让服务器被完全接管](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070714&idx=3&sn=bbdd11d7e9a7fce59dacff4dec6304db&scene=21#wechat_redirect)  
  
  
  
[【安全圈】英国Co-op超市证实650万会员数据遭窃，四名黑客落网](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070714&idx=4&sn=59ab7d07c936d969e09f9de15896e102&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
