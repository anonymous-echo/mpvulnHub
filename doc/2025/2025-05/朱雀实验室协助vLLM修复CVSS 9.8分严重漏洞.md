#  朱雀实验室协助vLLM修复CVSS 9.8分严重漏洞   
原创 腾讯朱雀实验室  腾讯安全应急响应中心   2025-05-22 03:24  
  
> 作者：Kikay、Nicky  
> 腾讯朱雀实验室发现vLLM推理框架存在严重安全漏洞（CVE-2025-47277，CVSS 9.8分），攻击者可利用此漏洞控制GPU服务器，窃取模型、算力或中断服务。vLLM团队已修复该漏洞并致谢腾讯朱雀实验室。  
  
  
  
1. vLLM框架的重要性与安全挑战  
  
vLLM是一个专为大型语言模型（LLM）推理设计的高性能框架，通过创新的内存管理和计算加速技术，显著提升吞吐量并降低延迟，特别适用于企业级高并发场景。作为一个社区驱动的开源项目，vLLM融合了学术界与工业界的智慧，在GitHub上收获了47K Star的关注度。目前，包括腾讯在内的众多企业广泛使用vLLM进行AI模型推理，其安全性直接关系到AI服务的稳定性和数据安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP4ia4mD7t0p4GoNQFRPQAib9DmLFyKqTacSVJ3vDQU9z9bvts3MR6nTEJEokV33R9dsQzLuLBhfc6Tg/640?wx_fmt=png&from=appmsg "")  
  
然而，vLLM的高普及度也使其成为攻击者的潜在目标。此前，vLLM曾曝光过两个位于MooncakePipe服务的严重漏洞。而本次由朱雀实验室发现的漏洞则存在于vLLM的PyNcclPipe服务中，攻击者可通过发送定制化的恶意数据包，远程获取GPU算力服务器控制权限，CVSS评分（通用漏洞评分系统，满分10分）高达9.8分。这一发现不仅揭示了新的安全风险，也为vLLM框架的漏洞研究提供了全新视角。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP4ia4mD7t0p4GoNQFRPQAib9DuXkjO1OHeEHQrxRWdFf0w51P7caIqia0OFvibpibJcNOeXk78ASTZkYrw/640?wx_fmt=png&from=appmsg "")  
  
为保障混元大模型及相关AI软件供应链的安全，朱雀实验室近两年来已帮助腾讯业务提前发现与排雷了英伟达、Hugging Face和PyTorch等多个知名AI组件的严重漏洞风险，并推出了开源工具AI-Infra-Guard（ https://github.com/Tencent/AI-Infra-Guard ），帮助社区与腾讯业务快速评估AI基础设施的安全风险。  
## 2. 漏洞原理与利用场景  
  
vLLM作为当前最受欢迎的推理框架之一，支持单机多卡和多机多卡推理，以降低对显卡性能的需求。在处理分布式GPU节点间的张量通信时，vLLM可选使用NVIDIA的NCCL（NVIDIA Collective Communications Library）技术。NCCL专为分布式多GPU计算环境设计，通过高效的张量集合操作实现数据通信与同步。  
  
在vLLM中，PyNcclPipe类负责构建支持NCCL的通信域，实现分布式GPU节点间的高效数据传输：  
  
● GPU侧：通过PyNcclCommunicator类传输KV-Cache数据；  
  
● CPU侧：通过send_obj和recv_obj方法处理控制消息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP4ia4mD7t0p4GoNQFRPQAib9D59cdKuhdmFeagLKvjIxOLEhibHF9ddCVRiaEic4x6znuRDKz2RwpBDAaA/640?wx_fmt=png&from=appmsg "")  
  
官方示例代码可参考：  
https://github.com/vllm-project/vllm/tree/main/tests/kv_transfer  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP4ia4mD7t0p4GoNQFRPQAib9DJNJx1j6ibLAPPPJpUmMsJ5PcEThkibYENwQ1bqWsSfI1VTjGrPIDYavA/640?wx_fmt=png&from=appmsg "")  
  
通过AI自动化代码审计结合人工验证，朱雀实验室发现，当PyNcclPipe服务接收到外部恶意客户端发来的不安全数据流时，会触发pickle反序列化漏洞，导致远程命令执行（RCE）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP4ia4mD7t0p4GoNQFRPQAib9DJOPaxtN2oKV5tC3lY87QJoY7T0g1lrI7tWj6ibIZNVQ0bfLrn70s5IQ/640?wx_fmt=png&from=appmsg "")  
  
攻击者可利用此漏洞控制服务器，窃取模型文件，甚至进一步渗透GPU算力集群等内网平台，造成以下严重后果：  
  
● 大规模数据泄露：敏感模型和数据被窃取；  
  
●   
算力窃取：攻击者占用GPU资源进行非法计算；  
  
● 服务中断：AI服务不可用，影响业务连续性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP4ia4mD7t0p4GoNQFRPQAib9DAtkJfDfibiaadJLWz4vOEBa2rB94UQoib2PV8nvKBcj5uSWZm8iauHoJQw/640?wx_fmt=png&from=appmsg "")  
  
典型场景下的漏洞利用流程如下：  
  
● 服务端创建PyNcclPipe服务，接受远程节点通信数据；  
  
● 攻击者构造恶意数据包并发送至PyNcclPipe服务；  
  
● 攻击者成功“getshell”，获取服务器控制权并实施后续攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP4ia4mD7t0p4GoNQFRPQAib9DuyJrfqyiahO9M7BpkchQC7xbtNTqY9lyTG0U6Wx0C5rHV1iavNu2mG5w/640?wx_fmt=png&from=appmsg "")  
## 3. 安全自查与缓解措施  
  
朱雀实验室发现漏洞后，迅速向vLLM开发团队提供了详细的技术分析和复现步骤，助力团队快速定位问题。目前vLLM最新版本已修复该漏洞（版本号为0.8.5），并在邮件中致谢朱雀实验室。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP6RBoQbsCqNxp6F0MGn1FU1VPicTUtDjU1eE59je6gYiaSxXTwDvOyUTpR2uhfHSfaoeYgllnv9pwdg/640?wx_fmt=png&from=appmsg "")  
  
为帮助vLLM社区与公司业务快  
速自查，朱雀实验室开源的AI-Infra-Guard已新增对此漏洞的扫描功能，用户可通过该工具快速评估现有vLLM组件是否受影响。若需进一步确认，可检查服务器代码是否调用了PyNcclPipe模块，并核查相关服务端口是否外部可访问。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JMH1pEQ7qP4ia4mD7t0p4GoNQFRPQAib9DSw9bdlfeCxP3gaGRyGCy40WzhSdrIowvy6byVVCsHx3K8MB90a3WSw/640?wx_fmt=png&from=appmsg "")  
## 4. 安全建议  
  
为确保vLLM在大模型推理场景的安全使用，朱雀实验室建议：  
  
● 尽快更新：升级至最新版本的vLLM以修复漏洞；  
  
● 容器化部署：使用容器技术隔离vLLM服务，配合网络策略限制访问；  
  
● 访问控制：对外开放服务时，严格限定可信IP地址；  
  
详细安全指引可参考官方文档：  
  
 https://docs.vllm.ai/en/latest/deployment/security.html 。  
  
  
## 5. 参考链接  
  
  
https://github.com/vllm-project/vllm  
  
https://github.com/vllm-project/vllm/security/advisories/GHSA-hjq4-87xh-g4fv  
  
  
  
  
  
  
