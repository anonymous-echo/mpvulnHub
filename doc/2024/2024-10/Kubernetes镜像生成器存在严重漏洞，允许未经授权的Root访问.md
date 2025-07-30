#  Kubernetes镜像生成器存在严重漏洞，允许未经授权的Root访问   
会杀毒的单反狗  军哥网络安全读报   2024-10-19 09:00  
  
**导****读**  
  
  
  
Kubernetes
Image Builder 中存在一个严重的安全风险 (CVE-2024-9486)，允许未经授权的 root 访问，对容器化环境构成严重威胁。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGz3HWI4uPpdm0ZfiaeWUQkwUKBPKafiaykO5RTMtcDhVia1cLAf28277fCUI5KsSdiaHrGsom59MVzeg/640?wx_fmt=webp&from=appmsg "")  
  
  
Kubernetes
Image Builder 出现了新的安全风险，对使用此工具管理容器化环境的组织构成了严重威胁。Kubernetes Image Builder 漏洞编号为
CVE-2024-9486，CVSS 评分为 9.8，表明其严重性。  
     
  
  
如果被利用，Kubernetes
Image Builder 中的这个漏洞可能允许未经授权的用户在特定情况下获得节点的 root 访问权限，从而给受影响的系统造成潜在的混乱。  
    
  
### Kubernetes 镜像生成器漏洞概述  
  
  
该严重漏洞由安全研究员
Nicolai Rybnikar发现，它允许默认凭据在镜像构建过程中保持启用状态。  
  
  
Red Hat的 Joel Smith详细阐述了这个问题，他表示：“在
Kubernetes Image Builder 中发现了一个安全问题，在镜像构建过程中默认凭据处于启用状态。  
     
  
  
此外，使用
Proxmox 提供程序构建的虚拟机镜像不会禁用这些默认凭据，这意味着使用这些镜像的节点可以通过这些凭据访问。”  
    
  
  
Kubernetes
Image Builder 中的这个漏洞影响深远。  
  
  
使用 Image
Builder 项目及其 Proxmox 提供程序构建的虚拟机镜像的集群面临风险，因为这些镜像可能会为攻击者提供获取root
访问权限所需的凭据。  
  
  
这可能导致对节点的未经授权的控制，从而影响整个 Kubernetes 集群的完整性和安全性。  
    
  
### 受影响的版本  
  
  
Kubernetes
Image Builder漏洞特别影响 0.1.37 及更早版本。使用这些版本与 Proxmox 提供程序的集群特别容易受到影响。  
  
  
相比之下，使用其他提供程序构建的镜像不存在此漏洞，尽管可能存在相关问题（如问题
#128007 中所述）。  
  
  
Kubernetes
Image Builder 中的这个漏洞的 CVSS 评分为 9.8，可能会造成严重影响，不仅会影响集群的直接安全性，还会影响其运行完整性。  
  
  
安全专家敦促各组织更新到最新版本的
Image Builder，实施建议的缓解策略，并持续监控其系统以防范潜在威胁。  
  
### 缓解步骤  
  
  
组织必须采取主动措施来解决
Kubernetes Image Builder 漏洞。首先，使用修补版本的 Image Builder  
  重建任何受影响的镜像至关重要。  
  
  
0.1.38
版本修复了该漏洞并引入了两个重大变化：它在镜像构建期间设置一个随机生成的密码，并在完成后禁用构建者帐户。  
  
  
在此期间，组织可以通过禁用受影响虚拟机上的
builder 帐户来降低风险。这可以通过执行命令 usermod -L builder 来实现。  
    
  
  
为了持续的安全，管理员应定期检查是否有任何登录到
builder 帐户。他们可以使用命令 last builder 来执行此操作。  
   
  
  
如果发现漏洞证据，应立即向security@kubernetes.io报告。采取这些措施将有助于组织保护其环境免受潜在威胁。  
    
  
### 结论  
  
  
Kubernetes
Image Builder 中的 CVE-2024-9486 漏洞凸显了在容器化环境中保持更好的安全实践的重要性。  
  
  
该漏洞的 CVSS
评分为 9.8，存在严重风险，尤其是对于使用受影响版本的 Proxmox 提供商的组织而言。  
    
  
  
立即采取行动至关重要：**升级到
0.1.38 版本****是保护系统免受未经授权的访问和潜在混乱的必要步骤。**  
  
  
此外，实施建议的缓解策略并定期进行安全审核将有助于保护系统免受此漏洞和未来漏洞的攻击。  
  
  
更多信息，可参考：  
https://github.com/kubernetes/kubernetes/issues/128006  
  
  
**链接：**  
  
https://thecyberexpress.com/kubernetes-image-builder-vulnerability/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
