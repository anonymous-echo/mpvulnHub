#  漏洞风险提示 | 泛微 Ecology OA SQL 注入漏洞   
长亭技术沙盒  黑伞安全   2023-04-23 18:28  
  
        长亭漏洞风险提示         
  
#   
泛微 Ecology OA SQL 注入漏洞#   
  
  
泛微协同管理应用平台(e-cology)是一套兼具企业信息门户、知识文档管理、工作流程管理、人力资源管理、客户关系管理、项目管理、财务管理、资产管理、供应链管理、数据中心功能的企业大型协同管理平台。Ecology 官方在 4 月 18 日发布了补丁更新，修复了一处由墨云科技安全研究员报送的 SQL 注入漏洞。  
**漏洞描述**  
  
泛微 Ecology OA 系统由于对用户传入的数据过滤处理不当，导致存在 SQL 注入漏洞，远程且未经过身份认证的攻击者可利用此漏洞进行 SQL 注入攻击，从而可窃取数据库敏感信息。长亭科技安全研究员经过分析后确认此漏洞同时影响 Ecology 9 和 8 两个版本系列，使用泛微 Ecology 的用户需尽快进行补丁更新升级。检测工具远程检测工具:复制链接https://stack.chaitin.com/tool/detail?id=1  前往xray - CT Stack 安全社区下载最新版本xray。执行：./xray ws --poc poc-yaml-weaver-ecology-oa-plugin-checkserver-setting-sqli --url http://example.com  即可扫描。本地检测工具:复制链接https://stack.chaitin.com/tool/detail?id=758 前往 CT Stack 安全社区下载牧云本地检测工具。  
  
**影响范围**  
  
泛微 ecology 9.x 补丁版本号 <= v10.56泛微 ecology 8.x 补丁版本号 <= v10.56  
  
**解决方案**  
  
  
目前官方已发布安全补丁进行漏洞修复，用户可通过更新升级安全补丁至 v10.57 版本进行漏洞修复： https://www.weaver.com.cn/cs/securityDownload.html?src=cn  
  
产品支持雷池：默认支持该漏洞检测全悉：默认支持该漏洞利用行为的检测云图：默认支持该产品的指纹识别，同时支持该漏洞的PoC原理检测洞鉴：自定义POC原理扫描检测牧云:   发布本地检测小工具  
**参考链接**  
  
  
- https://www.weaver.com.cn/cs/securityDownload.html?src=cn  
  
- https://mp.weixin.qq.com/s/MbGaTNNYSlJlQeqQ-5_KSw  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC7ia5uzmRe9JvNErXe95W4qTgEKhVa7kdaxpwJXC0oKXeFt5vGN4KmJv2mvcYkYtrd7cev0vkAhY7A/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicTqSickDYMicPRSanVuOHd14j3lWcUMibepSRgp7CTjegGVFiaoV9UDRVlgH96lNbLVRic8vhWxQbnIrVg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
