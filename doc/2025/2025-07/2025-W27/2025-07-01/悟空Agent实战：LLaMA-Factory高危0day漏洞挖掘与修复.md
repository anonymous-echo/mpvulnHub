> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NzE1NjA0MQ==&mid=2651207230&idx=1&sn=be1b2877b624966bf5393397469e9f94

#  悟空Agent实战：LLaMA-Factory高危0day漏洞挖掘与修复  
 腾讯安全应急响应中心   2025-07-01 10:05  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/j3gficicyOvasVeMDmWoZ2zyN8iaSc6XWYj79H3xfgvsqK9TDxOBlcUa6W0EE5KBdxacd2Ql6QBmuhBJKIUS4PSZQ/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
作者：腾讯悟空团队 — 新一代 AI 代码安全捉“妖”行者（原腾讯AI安全-啄木鸟团队)  
  
在  
前文[《0day漏洞量产？AI Agent“生产线”曝光！》](https://mp.weixin.qq.com/s?__biz=MjM5ODYwMjI2MA==&mid=2649793732&idx=1&sn=59278d0b2074a9c856a0700dfac2b83d&scene=21#wechat_redirect)  
中，我们揭示了悟空AI Agent的架构与自动化漏洞挖掘能力。本次，我们将以53K Star的开源明星项目LLaMA-Factory为战场，详细展示悟空AI Agent如何在实际场景中，精准挖掘高危远程代码执行  
0  
day  
漏洞（CVE-2025-53002），并推动官方修复的技术实战。  
  
### 一、LLaMA-Factory简介  
  
LLaMA-Factory  
是一个功能强大且用户友好的开源框架，在 GitHub 上斩获了超过 53K Stars，专注于大语言模型（LLM）的高效微调（Fine-tuning）。凭借其易用性和灵活性，LLaMA-Factory 已成为许多开发者和研究团队进行模型训练与部署的首选工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvav75ZsABYYfS0icVlXoticev6A5fibBGiakicy7gp8hPqIjBqhibt9zLJhSOGe4xrGGJTDChuXxMswE1TRA/640?wx_fmt=png&from=appmsg "")  
  
  
（图：LLaMA-Factory Github   
Index  
）  
  
然而，面对这样的大型开源社区项目，当我们使用悟空AI Agent对其进行深度安全审计时，也能发现潜在的安全风险，成功识别了一个严重的远程代码执行漏洞：CVE-2025-53002（CVSS v3.1: 8.3）。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvav75ZsABYYfS0icVlXoticev6hLZuicgd9YDTOAHp82z5hTMb6icz8aRkNuIuC18FDAG7cSmZqs6FmmYg/640?wx_fmt=png&from=appmsg "")  
  
  
（  
图  
：  
LLaMA-Factory Github  
  
Star  
  
History  
）  
  
### 二、悟空AI Agent的实战效能  
  
悟空AI Agent在此次漏洞挖掘中展示了其强大的自动化漏洞挖掘能力，特别是在多智能体协作架构（Multi-Agent）的支持下，突破了传统手段的限制。通过以下几个关键阶段，悟空AI Agent逐步发现了漏洞的核心  
：  
  
●  
   
Audit Agent：   
首先，  
Audit Agent负责从  
  
Web UI  
  
输入追踪到后台的数据处理参数及接口  
，  
从入口出发追踪目标数据流，并自动决策对下层调用函数的展开分析，直至发现存在漏洞特征的危险函数调用（不安全的反序列化 API 调用）。  
  
●  
   
Review Agent： 随后，Review Agent  
  
对 Audit Agent  
  
所提取的漏洞相关代码信息进行进一步分析，通过多重校验与投票机制评估该漏洞触发的约束条件，确定其可利用性。  
  
●  
   
Fix Agent：  
最终  
，  
Fix Agent基于CVEs数据库和内部知识库生成了漏洞修复建议，形成了具体的修复方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvav75ZsABYYfS0icVlXoticev6ZCZzlEXSZl2hFAAfZapMEwUrx0z3BicPFhgb0R3YEa4tYzkCVSBkUUQ/640?wx_fmt=png&from=appmsg "")  
  
  
（图：悟空  
  
AI  
 Agent   
架构  
图）  
  
悟空  
  
AI Agent  
  
在此过程中展现了卓越的  
程序分析与漏洞发现  
能力，能够穿透复杂逻辑链，精确定位到不安全的反序列化操作（  
torch.load  
）及其触发路径。  
悟空  
  
AI Agent  
  
不仅为传统的漏洞挖掘方法提供了补充，也为自动化安全审计提供了可行的解决方案。  
  
### 三、官方响应与修复  
  
在确认该漏洞有效后，我们立即通过GitHub Security Advisories渠道向LLaMA-Factory官方团队提交了详尽的技术报告（含PoC复现步骤，已同步报送CNVD等监管单位）。  
## 官方响应：  
  
 LLaMA-Factory团队对此高度重视，迅速确认了漏洞的有效性和严重性。并颁发CVE漏洞编号。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvav75ZsABYYfS0icVlXoticev6GgDiaP3bWNv2BWW5SP1WaTkJWGzgUN9OaaWPzI96pNRMdB9AE5hCAQQ/640?wx_fmt=png&from=appmsg "")  
  
  
（图：  
Github官方项目Security公告  
）  
## 修复方案：  
  
官方对  
src/llamafactory/model/model_utils/valuehead.py  
 的关键代码进行了加固：在  
torch.load()  
调用中  
显式添加了安全参数   
weights_only=True  
，从根本上阻断了利用Pickle反序列化执行任意代码的可能性。  

```
```

  

```
# src/llamafactory/model/model_utils/valuehead.py  

- state_dict = torch.load(vhead_file, map_location=&#34;cpu&#34;)  

+ state_dict = torch.load(vhead_file, map_location=&#34;cpu&#34;, weights_only=True)  

```

  
  
▲   
关键补丁：启用PyTorch安全模式阻断反序列化攻击  
  
### 四、 技术分析  
## 漏洞摘要   
  
在 LLaMA Factory 的训练过程中  
，  
发现一处严重的远程命令执行（RCE）漏洞。该漏洞源于加载   
vhead_file  
 时未采取充分的安全措施。恶意攻击者仅需通过 WebUI 界面传递一个恶意的   
Checkpoint path  
 参数，即可在宿主系统上执行任意恶意代码。整个攻击过程具有隐蔽性，受害者难以察觉。漏洞的根本原因是加载   
vhead_file  
 参数时，未设置安全参数   
weights_only=True  
。  
> 注意：  
 在 torch 版本 < 2.6 中，  
torch.load()  
 的默认设置为   
weights_only=False  
。而 LLaMA Factory 的   
setup.py  
 仅要求   
torch>=2.0.0  
，使得受影响版本默认处于不安全状态。  
>   
  
  
影响范围  
  
该漏洞影响的范围包括所有使用LLaMA-Factory框架的版本（<=0.9.3）。受影响的产品涉及广泛的应用场景，包括大语言模型的训练与推理。  
  
风险等级  
  
CVSS 3.1评分为8.3（高危），表明该漏洞对安全性构成了极大的威胁。  
  
CVE-2025-53002漏洞的存在使得攻击者能够通过精心构造的恶意文件，在LLaMA-Factory框架中实现远程代码执行，严重威胁使用该框架进行大语言模型训练和推理的组织。  
  
成功利用此漏洞后，攻击者能够执行任意恶意代码，可能导致权限提升、信息泄露、数据篡改等一系列恶劣后果，甚至可能破坏整个AI基础设施的安全性。  
## 漏洞触发流程  
  
1.   
在 LLaMA Factory 的 WebUI 中，当用户设置   
Checkpoint path  
 时，该值会修改传递给训练过程的   
adapter_name_or_path  
 参数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvav75ZsABYYfS0icVlXoticev6X3JIxuiaf49B2XaVra1mvJNiac3GJsEicSibibuzme4jjMrlYxbYG5CFYJg/640?wx_fmt=png&from=appmsg "")  
  
  
（图：相关代码位置：  
src/llamafactory/webui/runner.py  
）  
  
2.   
训练过程中使用的   
adapter_name_or_path  
 参数，在   
src/llamafactory/model/model_utils/valuehead.py  
 文件中用于从 Hugging Face 获取对应的   
value_head.bin  
 文件。  
  
3.   
随后，该文件通过   
torch.load()  
 加载，  
但未设置安全参数   
weights_only=True  
，最终导致远程代码执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvav75ZsABYYfS0icVlXoticev6gMkOpRjKicvXog7O4uIzibPAqtxYTmfBiaLxld1vlwvjP2IOv1GkWFicXQ/640?wx_fmt=png&from=appmsg "")  
  
  
（图：  
相关代码位置：  
src/llamafactory/model/model_utils/valuehead.py  
）  
  
### 结语  
  
本次对LLaMA-Factory的实战审计，展示了悟空AI Agent在真实、复杂开源项目中发现高危漏洞的效率与能力。它不仅缩短了漏洞从潜伏到被发现的时间窗口，也通过标准化的报告流程加速了厂商响应与修复。未来，AI Agent将在网络安全领域扮演越来越核心的角色：  
  
1.   
自动化深度审计  
：实现对大型项目、复杂代码的高效、深度、持续的全自动安全审查。  
  
2.   
0day威胁预警  
：主动挖掘未知漏洞，从漏洞利用链上精准识别0day漏洞，提升整体防御前置性。  
  
3.   
安全开发左移  
：集成至CI/CD流程，辅助开发者在早期规避安全缺陷，降低修复成本。  
  
  
悟空AI Agent的探索将持续深化，致力于推动安全研究与实践迈入智能化新纪元。  
  
