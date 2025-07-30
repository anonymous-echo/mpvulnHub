#  AI 安全 近日大模型推理引擎 vLLM 暴出CVSS 9.8高危rce   
K1T0  InXSec   2025-06-02 09:53  
  
# 一、CVE-2025-47277  
  
近日 vllm的通信组件pyncclpipe 被爆出存在相关高危rce漏洞，cvss评分高达9.8分。**vLLM**  
 是一个基于 **高效注意力算法（如 PagedAttention）**  
 构建的高性能语言模型推理引擎。它专为大规模语言模型（LLM）的 **服务化部署和推理加速**  
 而设计。  
# PyNcclPipe 是 vLLM 中用于实现 节点间张量通信（Tensor Communication） 的一个核心组件。它是基于 NCCL（NVIDIA Collective Communications Library） 或者 socket 实现的，用于在多个 GPU 或多个节点之间高效地传输张量数据（如 KV Cache）。  
# 二、影响版本  
  
=0.6.5,<0.8.5 目前0.8.5版本已经修复相关漏洞  
# 三、相关细节  
  
目前官方poc 已经公布，原理就是pyncclpipe组件进行通信时，在将字节流数据进行反序列化时候采用的方式是pickle反序列化，因此如果pyncclpipe 组件接口暴露在外，就容易受到相关攻击，危害极大。  
  
目前官方已经发布复现步骤 同时In_X 安全团队已经成功复现相关漏洞情况，已经集成相关poc，并针对相关漏洞在代码层面找到相关问题，具体细节可以@一起讨论.  
  
![CVE-2025-24054：NTLMハッシュ漏洩の脆弱性が ...](https://mmbiz.qpic.cn/sz_mmbiz_jpg/7JjdmCLfe2oo43mdTTbkhNUjiaajzxPr1HckV4fooApQueV7NPzgnoq01ic2eJWH2GlUU2Ow4XnsOVqIGrticjhvQ/640?wx_fmt=jpeg&from=appmsg "")  
  
