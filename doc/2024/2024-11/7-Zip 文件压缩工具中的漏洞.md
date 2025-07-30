#  7-Zip 文件压缩工具中的漏洞   
原创 很近也很远  网络研究观   2024-11-23 15:51  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxNZP7yicxhgOrjRVkTibkLEoHtr4NibW9IBhxqkViaeeusicINrhBlbMmu2icM3boGfsHh7hkaHXtp0e4hA/640?wx_fmt=png&from=appmsg "")  
  
7-Zip 文件压缩工具中  
发现了一个漏洞，  
允许攻击者通过特制的存档远程执行恶意代码。  
  
为了解决这个问题，开发人员发布了一个必须手动安装的更新，因为该程序不支持自动安装更新。  
  
该  
漏洞  
报告为 CVE-2024-11477，CVSS 严重性评分为 7.8，是由于使用 Zstandard 算法处理压缩文件时输入验证不足造成的。  
  
这可能导致内存溢出和恶意代码注入。   
  
Zstandard由于其高压缩速度和效率而广泛应用于Btrfs、SquashFS和OpenZFS等系统以及HTTP压缩。  
  
攻击者可以通过向 7-Zip 用户发送特制档案（例如通过电子邮件或网络共享）来利用此  
漏洞  
。  
  
打开此类文件可能会引入恶意代码。  
  
该问题由趋势科技零日  
计划的研究人员于 2024 年 6 月发现，并在 7-Zip 版本 24.07 中修复。  
  
目前更新版本24.08已经发布，可以从该程序的官方网站下载。  
  
建议用户安装最新版本，或者如果不需要使用 7-Zip，请卸载该程序。  
  
因为现代版本的 Windows 文件资源管理器默认支持 7-Zip 文件。  
  
