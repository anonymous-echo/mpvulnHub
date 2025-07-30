#  在野1day风险提示｜宏景人力系统 SQL注入漏洞（内附检测工具）   
 长亭安全应急响应中心   2023-05-11 18:55  
  
        长亭漏洞风险提示         
  
# 宏景人力系统 SQL注入漏洞  
# (CNVD-2023-08743)  
  
  
宏景人力资源管理系统是一款由宏景软件研发的系统，主要功能包括人员、组织机构、档案、合同、薪资、保险、绩效、考勤、招聘、培训、干部任免和人事流程等业务的管理，以及人事、绩效、培训、招聘、考勤等业务自助，还具备了报表功能和灵活的表格工具，支持集团管控、目标管理、领导决策等应用。近日，长亭应急团队监测到CNVD平台发布了北京宏景世纪软件股份有限公司人力资源信息管理系统存在SQL注入漏洞（CNVD-2023-08743）的通告，目前供应商发布了安全公告及相关补丁信息，修复了此漏洞。经过分析漏洞后，发现公网仍有较多系统未修复漏洞，长亭应急团队根据该漏洞的原理，编写了X-RAY远程检测工具供大家下载使用，同时在文章中提供了排查该资产的方式。远程检测工具：复制链接 https://stack.chaitin.com/tool/detail?id=1  前往xray - CT Stack 安全社区下载最新版本xray。执行：./xray ws --poc poc-yaml-hjsoft-hcm-codesettree-serlvet-categories-sqli --url http://example.com 即可扫描。  
**漏洞描述**  
  
由于系统未对用户的输入进行合理的处理，导致该系统存在SQL注入漏洞。攻击者可利用该漏洞获取数据库敏感信息。对攻击者来说，此漏洞的利用无需认证和鉴权，可通过该漏洞获取系统数据和用户数据，登录后台。影响范围最新版本以前的所有版本资产排查body_string = '<div class="hj-hy-all-one-logo"'  
**解决方案**  
  
  
安装官方提供的安全补丁产品支持云图：默认支持该产品的指纹识别，同时支持该漏洞的PoC原理检测。雷池：已发布虚拟补丁，支持该漏洞检测。全悉：已发布升级包，支持该漏洞利用行为的检测。洞鉴：已发布自定义POC，支持该漏洞检测。  
  
**参考资料**  
  
  
- http://www.hjsoft.com.cn/  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC7ia5uzmRe9JvNErXe95W4qTgEKhVa7kdaxpwJXC0oKXeFt5vGN4KmJv2mvcYkYtrd7cev0vkAhY7A/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicSsUMgo4OCUiaeInGVz2bG7cIxklywkXYrcicO44Uh4M4Glh9xAET0nkX8hialewaj8fmiadfMrstsB7Q/640?wx_fmt=png "")  
  
  
  
  
