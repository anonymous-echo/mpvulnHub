#  nuclei扫描漏洞实操及漏洞模版收集   
原创 qife  网络安全技术点滴分享   2025-04-05 09:28  
  
当收集到足够多的url后，即可开始做一些安全测试。nuclei可以加载各种安全漏洞模版对url进行测试，还支持根据最新的cve或者漏洞自定义开发模版。在这篇文章中，主要介绍nuclei启动安全测试以及漏洞模版收集。  
  
一、安装、运行nuclei  
1. 链接地址：  
https://github.com/projectdiscovery/nuclei.git  
  
1. 下载nuclei（windows 10环境）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE209M56qkdmoOgzm6XibYxxUxHiafnnZJ4WrjfJjfoViaKKlalZ62z1GkPZJibHkD6DGutQ745PQghzAwyA/640?wx_fmt=png&from=appmsg "")  
  
3.下载漏洞模版（当前下载官方提供的模版进行测试）  
  
下载链接：  
https://github.com/projectdiscovery/nuclei-templates.git  
  
4.运行nuclei检测收集的域名中是否存在安全漏洞，执行命令如下：  
```
//-l subdomains.txt 加载域名文件 -t E:\work\nuclei-templates 加载上面下载的漏洞模版 即可开始检测
nuclei.exe -l subdomains.txt -t E:\work\nuclei-templates
```  
  
结果如下所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/meR9vVNE209M56qkdmoOgzm6XibYxxUxHTMtQCsh91PQjJacy1bqVdFx4Cze5DmMcbObIztC4pOg43XlP3w8DEQ/640?wx_fmt=png&from=appmsg "")  
  
二、附上收集的nuclei模版可以放到扫描模版中，增加漏洞点扫描  
```
https://github.com/ping-0day/templates.git
https://github.com/samy1937/mynuclei_templates.git
https://github.com/reewardius/Nuclei-AI-Prompts.git
https://github.com/reewardius/nuclei-dast-templates.git
https://github.com/reewardius/nuclei-fast-templates.git
https://github.com/reewardius/aws-enumeration.git
https://github.com/reewardius/nuclei-excluded-templates.git
https://github.com/reewardius/iis-pentest.git
https://github.com/projectdiscovery/nuclei-templates.git
https://github.com/projectdiscovery/nuclei-templates-ai.git
https://github.com/projectdiscovery/fuzzing-templates.git
https://github.com/0xKayala/Custom-Nuclei-Templates.git
https://github.com/ronin-dojo/fuzzing-templates.git
https://github.com/YashVardhanTrip/nuclei-templates-initial-access.git
https://github.com/OWASP/www-project-asvs-security-evaluation-templates-with-nuclei.git
https://github.com/U53RW4R3/nuclei-fuzzer-templates.git
https://github.com/TNRooT/DeeP_RecoN.git
https://github.com/Haxxnet/FireAbend-NG.git
https://github.com/thanhnx9/nuclei-templates-cutomer.git
https://github.com/emadshanab/nuclei-templates-cutomer.git
https://github.com/Str1am/my-nuclei-templates.git
```  
  
