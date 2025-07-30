#  漏洞风险提示 | Gitlab CE&EE GraphQL添加恶意Runner漏洞   
长亭技术沙盒  黑伞安全   2023-05-09 10:18  
  
        长亭漏洞风险提示         
  
# Gitlab CE&EE GraphQL  
# 添加恶意Runner漏洞  
  
  
Gitlab是一款开源的代码管理平台，基于Ruby On Rails构建。该平台提供源代码管理、代码审核、问题跟踪、持续集成等功能。它能帮助开发者更高效地管理和协作开发项目，追踪代码变更并管理代码库的版本，同时也能提供web服务。近日，长亭科技监测到Gitlab发布了补丁更新，修复了一处后认证RCE漏洞。漏洞编号为CVE-2023-2478，CVSS评分9.6。  
**漏洞描述**  
  
任意gitlab用户可以通过GraphQL端点对任意项目添加恶意的Runner，进一步利用可能导致代码执行或敏感信息泄露。  
**影响范围**  
  
  
15.4 <= Gitlab CE&EE < 15.9.715.10 <= Gitlab CE&EE < 15.10.615.11 <= Gitlab CE&EE < 15.11.2  
  
**解决方案**  
  
  
目前官方已发布更新，受漏洞影响的用户可根据实际业务场景、确认在不影响业务的情况下对gitlab进行升级。https://about.gitlab.com/update/  
产品支持牧云：默认支持此软件的资产采集，对应的漏洞匹配升级包已经在升级平台上发布，版本号：23.05.008。云图：默认支持该产品的指纹识别。洞鉴：默认支持该产品的指纹识别。  
**参考资料**  
  
  
https://about.gitlab.com/releases/2023/05/05/critical-security-release-gitlab-15-11-2-released/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC7ia5uzmRe9JvNErXe95W4qTgEKhVa7kdaxpwJXC0oKXeFt5vGN4KmJv2mvcYkYtrd7cev0vkAhY7A/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicT31fEucm1w946icTuWBclHPDDBNIaL764yrOn7zhLLaoo1ILZHhpTqRjUia8GRjRCvbJicYAibRiaYvNQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
