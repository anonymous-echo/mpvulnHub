#  在野0Day漏洞预警｜Apache Druid远程代码执行漏洞（内附检测工具）   
 长亭安全应急响应中心   2023-04-19 10:36  
  
        长亭漏洞风险提示         
  
# Apache Druid远程代码执行漏洞  
  
  
Apache Druid是一个高性能的实时大数据分析引擎，支持快速数据摄取、实时查询和数据可视化。它主要用于OLAP（在线分析处理）场景，能处理PB级别的数据。Druid具有高度可扩展、低延迟和高吞吐量的特点，广泛应用于实时监控、事件驱动分析、用户行为分析、网络安全等领域。通过使用Druid，企业和开发者可以快速获得实时分析结果，提升决策效率。近期，Apache Kafka官方发布关于Apache Kafka Connect JNDI注入漏洞（CVE-2023-25194）的通告。这一漏洞需要低版本的JDK或者目标Kafka Connect系统中存在利用链，但由于该漏洞触发条件非常苛刻，几乎找不到可以利用的触发点。经过长亭安全研究团队分析漏洞后，发现Apache Druid正好符合Kafka CVE苛刻的利用条件，可以成功触发远程代码执行漏洞。长亭应急团队根据该漏洞的原理，编写了Xray远程检测工具和本地扫描工具供大家下载使用，同时在文章中提供了排查该资产的方式。远程检测工具：复制链接https://stack.chaitin.com/tool/detail?id=1  前往xray - CT Stack 安全社区下载最新版本xray。执行 ./xray ws --poc poc-yaml-apache-druid-kafka-rce --url http://example.com 即可扫描。注意，检测该漏洞需要配置反连平台。本地检测工具：复制链接https://stack.chaitin.com/tool/detail?id=735  前往 CT Stack 安全社区下载牧云本地检测工具。执行 ./apache_druid_rce_scanner_linux_amd64 scan 即可扫描。  
  
**漏洞描述**  
  
Apache Druid 支持从 Kafka 加载数据，恶意的攻击者可通过修改 Kafka 连接配置属性，从而进一步触发 JNDI 注入攻击，最终攻击者可在服务端执行任意恶意代码，获取系统服务权限。对攻击者来说，此漏洞的利用无需认证和鉴权，且默认配置下的 Apache Druid 即会受到此漏洞的影响。  
  
**影响范围**  
  
  
Apache Druid 全版本  
  
  
**资产排查**  
  
  
title_string = "Apache Druid"body_string = "Apache Druid console"根据指纹特征筛选出相关系统，尝试访问该系统，若无身份认证机制，漏洞即存在。  
  
  
**解决方案**  
  
  
为Apache Druid 开启认证配置：https://druid.apache.org/docs/latest/development/extensions-core/druid-basic-security.html  
  
  
产品支持云图：默认支持该产品的指纹识别，同时支持该漏洞的PoC原理检测。雷池：从5.3.8/4.6.8版本支持此漏洞检测。全悉：默认支持该漏洞利用行为的检测。洞鉴：使用自定义PoC可检测该漏洞，检测该漏洞需要配置rmi反连平台。牧云：默认支持对应资产的采集，漏洞匹配升级包（VULN-23.04.018）已经在升级平台上发布。谛听：从 DS-S(H)40-22.12.001 版本起支持此漏洞检测。  
**参考链接**  
  
  
https://druid.apache.org/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC7ia5uzmRe9JvNErXe95W4qTgEKhVa7kdaxpwJXC0oKXeFt5vGN4KmJv2mvcYkYtrd7cev0vkAhY7A/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FOh11C4BDicSupAK5Y1t5LQvgDbaoQEum4Wo6ExbTB760F56gsZgdoO2pUc3AwXqbeFkjtkzTxbfAcDiaGjibwGibQ/640?wx_fmt=png "")  
  
  
  
