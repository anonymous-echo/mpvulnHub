#  星图实验室协助vLLM项目修复多个高危漏洞   
星图实验室  奇安信技术研究院   2025-05-07 11:44  
  
****  
**01**  
  
  
**背景**  
  
vLLM 是一个高吞吐量、低内存占用的开源 Python 库，专为大型语言模型的推理和服务设计。它通过优化的内核和高效的资源管理，支持 AI 开发者在各种硬件平台上部署和运行大型语言模型，目前达到了46.4K的star数量。vLLM 的广泛应用使其成为 AI 社区的重要工具，但也因此成为攻击者的潜在目标。  
  
2025 年 4 月 29 日，vLLM 项目发布了安全更新，修复了多个安全漏洞。奇安信星图实验室的安全研究员协助 vLLM 项目修复了其中三个关键漏洞，分别是 CVE-2025-32444、CVE-2025-46560 和 CVE-2025-30202。这些漏洞可能被攻击者利用，引发拒绝服务攻击或远程代码执行，对使用 vLLM 的系统构成严重威胁。其中CVE-2025-32444的CVSS评分达到严重（10.0），成功利用可能导致攻击者完全控制服务器，执行恶意代码，窃取数据或破坏系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lG0evzxL96nAXTg36Rojf4dHeE5yvSrB8aiar5je7kCt1SwqzSrPaqLfWx27MxXU3dQbL8DxAqgDZtLxzI6864w/640?wx_fmt=png&from=appmsg "")  
  
**0****2**  
  
  
**漏洞详情**  
### CVE-2025-32444  
  
**vLLM Mooncake 集成远程代码执行漏洞**  
- **严重性：严重**  
  
- CVSS 3.1：  
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H（10.0）  
- **受影响版本：>= 0.6.5, < 0.8.5**  
- **已修复版本：0.8.5**  
**描述**  
： vLLM 在与 Mooncake 集成时，使用不安全的 pickle 序列化通过 ZeroMQ 套接字传输数据。由于这些套接字监听所有网络接口，未经身份验证的攻击者可以连接到开放端口并发送恶意 pickle 数据，从而在 vLLM 服务器上执行任意代码。此漏洞的攻击复杂度低，且无需用户交互，风险极高。  
  
**影响**  
： 仅使用 Mooncake 集成的 vLLM 实例受此漏洞影响。成功利用可能导致攻击者完全控制服务器，执行恶意代码，窃取数据或破坏系统。  
  
**代码位置**  
： https://github.com/vllm-project/vllm/blob/32b14baf8a1f7195ca09484de3008063569b43c5/vllm/distributed/kv_transfer/kv_pipe/mooncake_pipe.py#L179  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lG0evzxL96nAXTg36Rojf4dHeE5yvSrB71ziczce2ZsOicNcugPkAAbCLayP9ZgGYwAq9icNOAtBN4Chl7TUFue5A/640?wx_fmt=png&from=appmsg "")  
  
### CVE-2025-46560  
  
**vLLM input_processor_for_phi4mm 函数二次时间复杂度漏洞**  
- **严重性：中等**  
- **CVSS 3.1 向量：CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H（6.5）**  
- **受影响版本：>= 0.8.0, < 0.8.5**  
- **已修复版本：0.8.5**  
**描述**  
： 在 vLLM 的 input_processor_for_phi4mm 函数中，存在二次时间复杂度（O(n²)）的问题。攻击者可以通过构造包含大量占位符的输入数据，导致处理时间呈平方级增长，从而耗尽 CPU 或内存资源，引发拒绝服务攻击。例如，处理 10,000 个占位符可能导致约 1 亿次操作，显著降低系统性能。  
  
**影响**  
： 此漏洞允许具有网络访问权限的攻击者在无需高级权限的情况下触发拒绝服务，影响 vLLM 服务的可用性。  
  
**代码位置**  
： https://github.com/vllm-project/vllm/blob/8cac35ba435906fb7eb07e44fe1a8c26e8744f4e/vllm/model_executor/models/phi4mm.py#L1182-L1197  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lG0evzxL96nAXTg36Rojf4dHeE5yvSrB71ziczce2ZsOicNcugPkAAbCLayP9ZgGYwAq9icNOAtBN4Chl7TUFue5A/640?wx_fmt=png&from=appmsg "")  
  
### CVE-2025-30202  
  
**vLLM ZeroMQ XPUB 套接字配置不当漏洞**  
- **严重性：高**  
- **CVSS 3.1 向量：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H（7.5）**  
- ******受影响版本：>=0.5.2,<0.8.5**  
- **已修复版本:0.8.5**  
**描述**  
： 在多节点 vLLM 部署中，ZeroMQ XPUB 套接字被配置为绑定到所有网络接口，允许未经授权的客户端连接并接收内部 vLLM 状态数据。攻击者可通过发送大量连接请求或恶意数据包，减缓或阻塞发布者进程，从而引发拒绝服务攻击。  
  
**影响**  
： 此漏洞可能导致 vLLM 服务性能下降或完全不可用，影响多节点部署的稳定性。攻击者无需认证即可利用此漏洞。  
  
**代码位置**  
：  
- https://github.com/vllm-project/vllm/blob/c21b99b91241409c2fdf9f3f8c542e8748b317be/vllm/distributed/device_communicators/shm_broadcast.py#L236-L237  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lG0evzxL96nAXTg36Rojf4dHeE5yvSrB71ziczce2ZsOicNcugPkAAbCLayP9ZgGYwAq9icNOAtBN4Chl7TUFue5A/640?wx_fmt=png&from=appmsg "")  
  
  
**03**  
  
  
**建议措施**  
  
为确保系统安全，vLLM 用户应采取以下措施：  
1. **立即更新:将 vLLM 更新到版本 0.8.5 或更高版本，以修复所有上述漏洞。更新说明可参考 vLLM 官方文档。**  
1. **临时缓解措施********1)GHSA-hj4w-hm2g-p6w5：确保 vLLM 服务器不暴露在不受信任的网络中，并通过防火墙限制对 ZeroMQ 套接字的访问。********2)GHSA-9f8f-2vmf-885j：配置防火墙规则，仅允许受信任的主机访问 XPUB 套接字使用的 TCP 端口（端口为随机分配，需检查配置）。**  
1. **网络隔离：将 vLLM 部署在受控网络环境中，避免直接暴露在公共互联网上。**  
**04**  
  
  
**相关链接**  
- vLLM（https://github.com/vllm-project/vllm）  
  
- https://github.com/vllm-project/vllm/security/advisories/GHSA-vc6m-hm49-g9qg  
  
- https://github.com/vllm-project/vllm/security/advisories/GHSA-hj4w-hm2g-p6w5  
  
- https://github.com/vllm-project/vllm/security/advisories/GHSA-9f8f-2vmf-885j  
  
**05**  
  
  
**漏洞影响评估**  
  
以下表格总结了三个漏洞的关键信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/lG0evzxL96nAXTg36Rojf4dHeE5yvSrBfp3ZRpsmhjEBhicInD0ETQvLtoR9jcsaFf81mpOu8zNA7DOJqJjdl9A/640?wx_fmt=png&from=appmsg "")  
  
**06**  
  
  
**技术背景**  
  
vLLM 的设计依赖于高性能的分布式计算和网络通信，特别是在多节点部署中使用了 ZeroMQ 等技术。然而，网络接口配置不当或序列化机制的不安全使用可能引入严重的安全风险。例如，pickle 序列化在 Python 中因其可执行任意代码的特性而被认为不安全，尤其是在未受信任的网络环境中。类似地，ZeroMQ 套接字的默认配置可能导致意外的数据暴露或资源耗尽。  
  
**07**  
  
  
**社区响应**  
  
vLLM 项目团队迅速响应了这些漏洞报告，并在 0.8.5 版本中发布了修复补丁。社区用户被鼓励通过 vLLM GitHub 仓库 跟踪更新，并参与漏洞报告和修复工作。vLLM 还计划在未来的版本中增强安全设计，例如改进网络配置验证和序列化安全性。  
  
**08**  
  
  
**结论**  
  
这些漏洞的发现和修复凸显了开源软件安全的重要性。vLLM 作为 AI 领域的重要工具，其安全性直接影响众多应用场景。通过奇安信星图实验室和 vLLM 社区的协作，这些高危漏洞得以迅速修复，保障了用户系统的安全。用户应保持警惕，及时更新软件，并遵循最佳安全实践以降低风险。  
  
星图实验室隶属于奇安信技术研究院，专注于软件与系统安全的核心技术研究与系统平台研发，对外输出“天穹”软件动态分析沙箱、“天问”软件供应链分析平台、“天象”软件漏洞挖掘系统等核心能力和工具系统。  
  
  
我们目前正在招聘，工作地点覆盖北京、南京、成都等城市，详情请参见：  
  
https://research.qianxin.com/recruitment/  
  
  
  
