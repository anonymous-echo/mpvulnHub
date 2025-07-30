#  vLLM 曝高危远程代码漏洞，AI 服务器面临攻击风险   
 FreeBuf   2025-05-21 10:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![vLLM 漏洞示意图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39k7uSGyL3DIRgUVQGujfQ1ATlRUObTcy2XEgWL73KJuaAOTJ4Qqkm5mgXp7BqNTct2NGPctEv3vg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
研究人员近日披露了大型语言模型（LLM）高性能推理与服务引擎 vLLM 中存在的一个高危漏洞（编号 CVE-2025-47277）。该漏洞源于 PyNcclPipe 通信服务中存在的不安全反序列化缺陷，可导致远程代码执行（RCE），其 CVSS 评分为 9.8 分。  
  
### Part01  
### 漏洞技术细节  
  
  
vLLM 最初由加州大学伯克利分校 Sky Computing 实验室开发，现已成为社区驱动的开源项目，为 LLM 推理和服务提供快速易用的库。该工具支持分布式部署和先进的 KV 缓存管理，并能与工业级 LLM 基础设施集成。  
  
  
漏洞存在于 PyNcclPipe 类中，该类通过点对点消息传递实现分布式节点间的 KV 缓存传输。其 CPU 端消息传递机制使用 Python 的 pickle 模块进行数据序列化和反序列化。  
  
  
安全公告指出："PyNcclPipe 实现中存在严重安全缺陷，它直接使用 pickle.loads 处理客户端提供的数据，形成了可导致远程代码执行的不安全反序列化漏洞。"  
  
  
**Part02**  
### 攻击影响分析  
  
  
攻击者通过向运行的 PyNcclPipe 服务发送恶意构造的对象，即可利用该漏洞在主机上执行任意系统命令，从而完全控制服务器。  
  
  
该问题的根源还与 PyTorch 的 TCPStore 绑定行为有关："PyTorch 的默认行为是 TCPStore 接口会监听所有网络接口，无论提供的是何种 IP 地址。"  
  
  
**Part03**  
### 修复建议  
  
  
vLLM 已实施临时解决方案，确保绑定到指定的私有接口以降低暴露风险。建议用户立即升级至 vLLM v0.8.5 版本。  
  
  
**参考来源：**  
  
**Critical CVSS 9.8 RCE Flaw in vLLM Exposes AI Hosts to Remote Attacks**  
  
https://securityonline.info/critical-cvss-9-8-rce-flaw-in-vllm-exposes-ai-hosts-to-remote-attacks/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651320917&idx=3&sn=7dc05cb9d3ab151bf6da222ec282fb34&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
