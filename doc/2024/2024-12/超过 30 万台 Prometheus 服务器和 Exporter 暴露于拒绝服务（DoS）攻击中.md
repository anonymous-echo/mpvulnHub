#  超过 30 万台 Prometheus 服务器和 Exporter 暴露于拒绝服务（DoS）攻击中   
 独眼情报   2024-12-13 03:22  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnRpbyJrHELOcIkBEzz4y8ia2JxICOEqlY5wgOtWw7gtrtT92iczexnibjnRhFVic6hq9h4P2NHstibSR7w/640?wx_fmt=jpeg&from=appmsg "")  
  
在本研究中，我们揭示了Prometheus生态系统中的几个漏洞和安全缺陷。这些发现涵盖了三个主要领域：信息泄露、拒绝服务（DoS）攻击和代码执行。  
# 主要发现  
1. 暴露在外的Prometheus服务器或导出器，通常缺乏适当的身份验证，使攻击者能够轻松收集敏感信息，如凭据和API密钥。  
  
1. 我们识别出了一个令人担忧的拒绝服务（DoS）攻击风险，源于pprof调试端点的暴露，攻击者可利用这一漏洞使Prometheus服务器、Kubernetes容器和其他主机崩溃。  
  
1. 我们的调查还发现了一个名为"RepoJacking"的远程代码执行风险，攻击者可以通过被遗弃或重命名的GitHub仓库引入恶意导出器。  
  
# Prometheus是什么？  
  
Prometheus是一个开源的监控和告警工具包，已成为现代监控策略的基石。其核心架构包括：  
- 定期从目标系统抓取指标  
  
- 在本地时间序列数据库中存储这些指标  
  
- 提供强大的查询语言PromQL，用于实时数据分析  
  
该系统是模块化的，包括用于处理告警的Alertmanager和用于可视化的Grafana，使其非常适合Kubernetes等动态环境。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnRpbyJrHELOcIkBEzz4y8ia2oY5S29XhF5jRejwdLo0ibXicqb9160jUoHu9iaSp9cTLkfzZQn7ibsP58g/640?wx_fmt=png&from=appmsg "")  
# 研究发现  
## 信息泄露  
  
当Prometheus服务器或导出器连接到公共互联网且未经身份验证时，会带来极大的风险。这种错误配置允许任何人查询暴露的环境并列出标签或指标。攻击者可以利用这种访问权限收集看似微不足道的数据，并通过秘密扫描工具发现敏感信息，包括凭据、密码、认证令牌和API密钥。  
## 拒绝服务攻击  
  
研究团队重点分析了Prometheus及其关键组件中的Go调试接口（pprof包）。暴露在互联网上的/debug/pprof端点可被攻击者利用执行拒绝服务攻击。例如，向/debug/pprof/heap?seconds={i}端点发送多个同时请求，会强制服务器执行密集的性能分析操作，消耗大量CPU和内存资源。  
## 代码执行风险  
  
研究发现，几个Prometheus导出器容易受到RepoJacking攻击。攻击者可以声明文档中引用的现已可用的用户名，重新创建同名导出器并托管恶意版本。不知情的用户按照文档操作时，可能会无意中克隆和部署这些恶意导出器，从而在其系统上执行远程代码。  
# 风险数据  
  
研究显示，约336,000台服务器将Prometheus服务器和导出器暴露在互联网上，这种做法带来显著的安全风险。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnRpbyJrHELOcIkBEzz4y8ia2TwFTFWAPqPwuUkicFPBX7PETQzbv5BegdgKjG22kcMT8PIE1gclj0Vg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnRpbyJrHELOcIkBEzz4y8ia2EIhNTDctagXXQuNO5W6v4qXdNkWQC9fZNF0r4VvibwFRzibJaGnJm9Pw/640?wx_fmt=png&from=appmsg "")  
# 安全建议  
  
为了缓解这些风险，我们建议组织采取以下措施：  
1. **身份验证与授权**：使用适当的身份验证机制保护Prometheus服务器和导出器。  
  
1. **限制外部暴露**：尽量减少Prometheus在公共互联网上的暴露。在需要外部访问时，使用安全的通信通道。  
  
1. **监控和保护调试端点**：不要公开/debug/pprof端点，将调试和性能分析端点限制在内部使用。  
  
1. **限制资源耗尽**：设置CPU和RAM限制，防止或最小化拒绝服务攻击。  
  
1. **审查开源链接**：为避免供应链攻击，请确保下载项目的链接绝对正确和可靠。  
  
通过实施这些建议，组织可以显著提高其Prometheus监控基础设施的安全性。  
>   
> https://www.aquasec.com/blog/300000-prometheus-servers-and-exporters-exposed-to-dos-attacks/  
  
  
  
  
