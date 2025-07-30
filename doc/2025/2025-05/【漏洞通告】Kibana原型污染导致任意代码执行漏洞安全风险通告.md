#  【漏洞通告】Kibana原型污染导致任意代码执行漏洞安全风险通告   
 嘉诚安全   2025-05-08 00:44  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全  
监测到  
Kibana原型污染导致任意代码执行漏洞，漏洞编号为：  
CVE-2025-25014  
。  
  
  
ElasticKibana是一个开源数据可视化和分析平台，专为与Elasticsearch配合使用而设计。它允许用户通过图形界面直观地展示和探索数据，支持实时数据分析、日志监控和业务指标跟踪。Kibana提供强大的搜索、过滤和可视化功能，适用于大规模数据处理和展示。它常用于安全事件监控、日志分析、业务智能等领域，是ElasticStack（包括Elasticsearch、Logstash和Beats）的核心组件之一。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，  
攻击者可通过精心构造的HTTP请求，利用Kibana的机器学习和报告端点，可能导致任意代码执行。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
8.3.0<=Kibana<=8.17.5  
  
Kibana8.18.0  
  
Kibana9.0.0  
  
**处置建议**  
  
  
  
  
  
  
  
  
1.升级版本  
  
官方已发布安全更新，建议受影响用户尽快升级至8.17.6、8.18.1或9.0.1版本。  
  
下载链接：  
  
https://github.com/elastic/kibana/releases  
  
2.临时措施  
  
对于无法升级的用户，可以通过禁用机器学习或报告功能来缓解风险。自托管和ElasticCloud部署的用户可在kibana.yml文件中添加xpack.ml.enabled:false来禁用机器学习功能；若仅需禁用异常检测功能，自托管用户可添加xpack.ml.ad.enabled:false。同时，用户也可以通过在kibana.yml文件中添加xpack.reporting.enabled:false来禁用报告功能。  
  
3.通用建议  
  
定期更新系统补丁，减少系统漏洞，提升服务器的安全性。  
  
加强系统和网络的访问控制，修改防火墙策略，关闭非必要的应用端口或服务，减少将危险服务（如SSH、RDP等）暴露到公网，减少攻击面。  
  
使用企业级安全产品，提升企业的网络安全性能。  
  
加强系统用户和权限管理，启用多因素认证机制和最小权限原则，用户和软件权限应保持在最低限度。  
  
启用强密码策略并设置为定期修改。  
  
4.参考链接  
  
https://discuss.elastic.co/t/kibana-8-17-6-8-18-1-or-9-0-1-security-update-esa-2025-07/377868  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
