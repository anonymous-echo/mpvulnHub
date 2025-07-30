#  漏洞预警 | WordPress Elementor PDF生成器任意文件下载漏洞   
浅安  浅安安全   2024-12-06 00:00  
  
**0x00 漏洞编号**  
- CVE-2024-9935  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
WordPress Elementor页面生成器插件PDF生成器是一个专为WordPress网站设计的插件，特别适配Elementor页面构建器，旨在为用户提供PDF生成功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXspIn8EJLM6hcSZWI7RibP9BGKVAO3MhkZobfH1UicDODXNvajvuwIN7J8tx504ibOMS4xvfad31BUA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
CVE-2024-9935  
  
**漏洞类型：**  
任意文件下载  
  
**影响：**  
获取敏感信息  
  
**简述：WordPress Elementor页面生成器插件PDF生成器的/elementor-84接口存在任意文件下载漏洞，未经身份验证的攻击者可以通过该漏洞下载服务器任意文件，从而获取大量敏感信息。**  
  
**0x04 影响版本**  
- pdf-generator-addon-for-elementor-page-builder <= 1.7.5  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://cn.wordpress.org/plugins/pdf-generator-addon-for-elementor-page-builder/  
  
  
  
  
