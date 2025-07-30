#  【安全圈】TensorRT-LLM高危漏洞可导致攻击者远程执行代码   
 安全圈   2025-05-04 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
NVIDIA 在其 TensorRT-LLM 框架中披露并修补了一个高严重性漏洞，该漏洞可能允许具有本地访问权限的攻击者执行恶意代码、篡改数据并可能破坏 AI 系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgvN8bWrliaHIVwDWFSLgS9sMx4vlxhia5VentJQCerIjOf9zxUu2ro8WnXV5RjLC72Yqp4YAkC2RPg/640?wx_fmt=png&from=appmsg "")  
  
该漏洞被跟踪为 CVE-2025-23254，影响 Windows、Linux 和 macOS 平台上 0.18.2 之前的所有 TensorRT-LLM 版本。  
## TensorRT-LLM Python Executor 不安全的 pickle 处理  
  
安全研究人员在 TensorRT-LLM 的 Python executor 组件中发现了一个严重缺陷，特别是在其基于套接字的进程间通信 （IPC） 系统中。  
  
该漏洞源于对 Python 的 pickle 序列化/反序列化机制的不安全处理，该机制在处理不受信任的数据时以其安全风险而广为人知。  
  
CVE 的 CVSS 基本分数为 8.8，将其归类为高严重性。它属于常见弱点枚举类别 CWE-502（不受信任数据的反序列化），这是一个可能导致远程代码执行的已知漏洞类别。  
  
“任何平台的 NVIDIA TensorRT-LLM 都包含 python executor 中的漏洞，攻击者可能会通过本地访问 TRTLLM 服务器导致数据验证问题”，NVIDIA 在其安全公告中警告说。  
  
“成功利用此漏洞可能导致代码执行、信息泄露和数据篡改”。  
  
NVIDIA 感谢 Oligo Security 的 Avi Lumelsky 负责任地报告了该漏洞。  
  
<table><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="14330498" msthash="69" style="box-sizing: border-box;font-weight: bold;"><span leaf="">风险因素</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="3259074" msthash="70" style="box-sizing: border-box;font-weight: bold;"><span leaf="">详</span></strong></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">受影响的产品</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">NVIDIA TensorRT-LLM（0.18.2 之前的 Windows、Linux、macOS 版本）</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">冲击</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">代码执行、信息泄露、数据篡改</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">利用先决条件</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">对 TRTLLM 服务器的本地访问 （AV：L）、低攻击复杂性 （AC：L）、低权限 （PR：L）</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVSS 3.1 分数</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">8.8 （高）</span></section></td></tr></tbody></table>## 技术开发路径  
  
该漏洞特别涉及 Python 的 pickle 模块，该模块可以在反序列化过程中通过 __reduce__（） 方法执行任意函数。  
  
在 TensorRT-LLM 的案例中，对服务器具有本地访问权限的攻击者可以制作恶意序列化数据，当这些数据被应用程序反序列化时，将以正在运行的进程的权限执行任意代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgvN8bWrliaHIVwDWFSLgS9snouAQFibleUaPibbblU8l0pS6AOt0ta4DibGyt5LsbWnYCU7WgIX7mWAg/640?wx_fmt=png&from=appmsg "")  
  
  
TensorRT-LLM 的 IPC 实现中的 ZeroMqQueue 类特别容易受到攻击，因为它使用 pickle 跨进程序列化和反序列化数据，而无需进行适当的验证。  
## 已发布的补丁  
  
NVIDIA 于 2025 年 4 月 29 日发布了 0.18.2 版本，该版本在基于 socket 的 IPC 系统中默认实现了 HMAC（Hash-based Message Authentication Code）加密。  
  
此安全增强功能通过在反序列化之前验证序列化数据的完整性来防止漏洞被利用。  
  
该公司强烈建议所有用户立即更新到 0.18.2 或更高版本，并警告“禁用此功能将使您容易受到安全问题的影响”。  
  
对于无法立即升级的用户，NVIDIA 指出可以手动禁用加密功能，但强烈建议不要这样做：  
  
在 main 分支上，客户可以在 tensorrt_llm/executor/ipc.py 下的类 ZeroMqQueue 中设置 use_hmac_encryption = False。在 0.18 版本中，客户可以在 tensorrt_llm/executor.py 下的类 ZeroMqQueue 中设置 use_hmac_encryption = False。  
  
此漏洞凸显了 AI 框架中日益增长的安全挑战，尤其是那些处理复杂模型作的框架。  
  
TensorRT-LLM 广泛用于加速生成式 AI 的大型语言模型，显著提高生产应用程序的性能。  
  
敦促使用 TensorRT-LLM 的组织立即实施该补丁，以保护其 AI 基础设施免受潜在利用。  
  
  
   END    
  
  
阅读推荐  
  
  
[【安全圈】国家网络安全通报中心公布境外恶意网址和IP](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069416&idx=1&sn=515cc01e2351fc7bc0f1b62da0313900&scene=21#wechat_redirect)  
  
  
  
[【安全圈】迪士尼1.1TB数据泄露](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069416&idx=2&sn=f807df4735b9462cfb11efeda17a97a3&scene=21#wechat_redirect)  
  
  
  
[【安全圈】英国多家零售商遭遇网络黑客攻击](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069416&idx=3&sn=54ab1afc45b0f52d9482d1ff5ad86d27&scene=21#wechat_redirect)  
  
  
  
[【安全圈】IPv6 网络功能被滥用，劫持腾讯等软件更新重定向下载恶意软件](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069404&idx=1&sn=d894f9dd38ef94ee8376915b211e1989&scene=21#wechat_redirect)  
  
  
  
[【安全圈】迪士尼前员工因入侵服务器并篡改餐厅菜单获刑三年](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069404&idx=2&sn=d97069dd6bc0436c493dbba070d8c913&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
