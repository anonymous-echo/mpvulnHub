#  ShellTorch漏洞影响数万PyTorch模型服务器   
 关键基础设施安全应急响应中心   2023-10-12 14:59  
  
研究人员在TorchServe中发现多个高分漏洞，影响数万AI 服务器。  
  
TorchServe是由Meta和 Amazon负责维护的开源的PyTorch 模型服务库，可大规模部署经过训练的 PyTorch，无需编写自定义代码，被学术界和产业界广泛应用于人工智能模型训练和开发，包括亚马逊、OpenAI、特斯拉、Azure、谷歌、Intel等。  
# ShellTorch  
  
Oligo安全研究人员在开源的TorchServe AI模型服务工具中发现了3个高分安全漏洞——ShellTorch。攻击者利用这些漏洞可以实现非授权的服务器访问、远程代码执行等，影响数万联网服务器，其中部分服务器隶属于大型公司。  
  
ShellTorch漏洞是3个漏洞的集合，影响 TorchServe v0.3.0到v0.8.1版本，这3个漏洞分别是：  
  
1.滥用管理控制台（未经认证的管理接口API错误配置）：TorchServe会暴露多个接口，其中包括允许运行时管理模型的管理API接口。研究人员在其中发现一个错误配置漏洞，导致web panel默认在IP地址0.0.0.0而非localhost，会暴露外部请求。由于接口缺乏认证，任何用户都可以无限制访问，因此攻击者可以从外部地址上传恶意模型。  
  
2.CVE-2023-43654：第二个漏洞是恶意模型注入漏洞，CVSS评分9.8分，通过远程服务器端请求伪造伪造（SSRF）引发远程代码执行。TorchServe模型的配置文件可以使用workflow/model注册API来从远程URL取回。API中包含所允许的域名列表，研究人员发现默认情况下所有的域名都被认为是有效的，因此会引发SSRF。攻击者可以通过上传恶意模型来在目标服务器上触发任意代码执行。  
  
3.CVE-2022-1471：第三个漏洞是一个不安全的开源库使用漏洞，CVSS评分9.9分，漏洞产生的根源是一个Java 反序列化问题引发的远程代码执行。由于SnakeYAML库的不安全反序列化，攻击者可以上传包含恶意YAML文件的模型来触发远程代码执行。  
  
攻击者利用这三个漏洞就可以入侵运行有漏洞版本TorchServe的系统，ShellTorch攻击PoC视频参见：  
  
https://player.vimeo.com/video/870718937  
  
Oligo 研究人员发布了一个工具来检测其服务器实例是否受到ShellTorch攻击的影响，工具下载地址：https://github.com/OligoCyberSecurity/ShellTorchChecker  
# 补丁  
  
Oligo 研究人员分析发现有上万个IP地址（服务器）受到ShellTorch攻击的影响，为修复以上漏洞，建议用户：  
  
1.升级到TorchServe 0.8.2版本，但该版本未修复CVE-2023-43654 。  
  
2.将config.properties文件的管理地址（management_address）设置为http://127.0.0.1:8081来重新正确配置管理控制台。   
  
3.更新 config.properties文件中的allowed_urls，确保服务器只从可信域名取回模型。  
  
更多参见：  
  
https://www.oligo.security/blog/shelltorch-torchserve-ssrf-vulnerability-cve-2023-43654  
  
**参考及来源：**  
  
https://www.bleepingcomputer.com/news/security/shelltorch-flaws-expose-ai-servers-to-code-execution-attacks/  
  
  
  
原文来源：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
