#  紧急！问脉开源工具支持扫描 MinIO 敏感信息泄露漏洞   
 CT Stack 安全社区   2023-03-31 12:45  
  
「问脉独家」支持扫描 MinIO 敏感信息泄露漏洞（CVE-2023-28432）  
## 漏洞风险  
  
漏洞描述：在集群模式的配置下，MinIO 部分接口由于信息处理不当返回了所有的环境变量信息（包括 MINIO_SECRET_KEY 和 MINIO_ROOT_PASSWORD），从而导致敏感信息泄漏漏洞，攻击者可能通过获取到的密钥配置信息直接登陆操作 MinIO 接口。  
  
**只有 MinIO 被配置为集群模式时才会受此漏洞影响，此漏洞的利用无需用户身份认证，官方建议所有使用集群模式配置的用户尽快升级。**  
  
****  
  
  
影响范围  
：MinIO RELEASE.2019-12-17T23-16-33Z <= MinIO Version < MinIO RELEASE.2023-03-20T20-16-18Z  
  
  
  
官方信息  
：3月20日，MinIO 官方发布了安全补丁，修复了一处敏感信息泄露漏洞 CVE-2023-28432：https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q  
  
  
## 问脉专项插件介绍  
  
veinmind-minio 基于问脉引擎，快速识别并发现   
镜像/容器 中是否存在   
CVE-2023-28432 漏洞，文末阅读原文使用工具  
- 快速扫描容器/镜像中的minio CVE-2023-28432风险  
  
- 支持JSON/CLI/HTML等多种报告格式输出  
  
兼容性  
- linux/amd64  
  
- linux/386  
  
- linux/arm64  
  
- linux/arm  
  
****  
  
使用命令  
  
  
**./veinmind-minio scan [image/container]**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HSdSibDdRfuxENEVxArribd777J40YBkqdOsYl4OicgL6SkTh4YMlZZmX4SicUEJZFibVDT7roxybC6nhndiaZX9vVQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HSdSibDdRfuxENEVxArribd777J40YBkqCJAVKjhdKQCibArHyZ74SLyfgaN0ze9cERvQO2UomLQ208XicWwbMSsw/640?wx_fmt=png "")  
  
  
  
  
  
  
  
**扫码添加小助手，一起学习、共同进步！**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NtPFQib0CNabiaAiaCKn4Gj60LeAJYhtWJsgBAUnxFUV0dsqtlkOuhibUOglQKeXslRqkB3PNKbSH5BJHDLK0azkSw/640?wx_fmt=png "")  
  
  
问脉 Tools 社区版是长亭牧云团队孵化的一款开源容器安全检测工具集。目前已支持镜像/容器漏洞、逃逸风险、恶意文件、后门、敏感信息、弱口令、资产识别等扫描功能。  
  
为了提供更优质的服务，我们同时提供商业版牧云·云原生安全平台。首推零侵入探针，采用 Agentless 方案进行部署，保证业务节点实现严格意义上的零侵入检测，让用户能够轻装上阵，轻松解决云原生安全问题。  
  
👇点击阅读原文前往Github下载使用问脉工具，随手star的你最帅  
  
