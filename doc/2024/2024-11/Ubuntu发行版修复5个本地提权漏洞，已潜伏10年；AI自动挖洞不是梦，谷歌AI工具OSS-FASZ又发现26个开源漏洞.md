#  Ubuntu发行版修复5个本地提权漏洞，已潜伏10年；AI自动挖洞不是梦，谷歌AI工具OSS-FASZ又发现26个开源漏洞   
 黑白之道   2024-11-23 01:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
**Ubuntu发行版修复5个本地提权漏洞，已潜伏10年；**  
  
  
11 月 22 日消息，科技媒体 bleepingcomputer 于 11 月 20 日发布博文，报道称 Ubuntu Linux 发行版中潜伏 10 年的漏洞被发现，攻击者利用这些漏洞可以提升本地权限至 root 级别。  
  
Qualys 发现了这 5 个漏洞存在于 needrestart 实用工具中，追踪编号分别为 CVE-2024-48990、CVE-2024-48991、CVE-2024-48992、CVE-2024-10224 和 CVE-2024-11003。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/3xxicXNlTXL9O9HmGNBrY9TQCMEwgicSMjbYZIp0kHHeRDcPFLwLOicsHjXkAEyzA23DLaCKYqJ9Bzlh8vcfmvVFQ/640?wx_fmt=other&from=appmsg "")  
  
needrestart 是一个用于检查在库升级后哪些守护进程需要重新启动的实用程序，这些漏洞于 2014 年 4 月发布的 needrestart 0.8 版本中引入，在 2024 年 11 月 19 日发布的 3.8 版本中才修复。IT之家简要介绍下 5 个漏洞如下：  
  
CVE-2024-48990 和 CVE-2024-48992: 攻击者可通过控制 PYTHONPATH 和 RUBYLIB 环境变量，注入恶意共享库，从而在 Python 和 Ruby 解释器初始化期间执行任意代码。  
  
CVE-2024-48991: 利用 needrestart 中的竞争条件，攻击者可以替换 Python 解释器二进制文件，从而执行恶意代码。  
  
CVE-2024-10224: needrestart 使用的 Perl ScanDeps 模块对攻击者提供的文件名处理不当，允许攻击者构造类似 shell 命令的文件名来执行任意命令。  
  
CVE-2024-11003: ScanDeps 模块中不安全的使用 eval () 函数，导致在处理攻击者控制的输入时可能执行任意代码。  
  
**AI自动挖洞不是梦，谷歌AI工具OSS-FASZ又发现26个开源漏洞**  
  
  
  
谷歌透露，其基于人工智能的模糊工具OSS-Fuzz 已被用于帮助识别各种开源代码库中的26个漏洞，包括 OpenSSL 加密库中的一个中度漏洞。这一事件代表了自动化漏洞发现的一个里程碑：每个漏洞都是使用AI发现的，利用AI生成和增强的模糊测试目标。  
  
提到的OpenSSL漏洞是CVE-2024-9143（CVSS评分：4.3），一个超出范围的内存写入缺陷，可能导致应用程序崩溃或远程代码执行。这个问题已经在OpenSSL的3.3.3、3.2.4、3.1.8、3.0.16、1.1.1zb和 1.0.2zl版本中得到了解决。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylgKZbN7RO3qZzvWgQTAPicibNibCIuDA4rpe9RKsNiasSueNB1LzwqJNHoz6r4YjSlVRSEPHE6cY1Aeibg/640?wx_fmt=jpeg&from=appmsg&wxfrom=13 "")  
## 破题人类无法发现的漏洞  
  
谷歌在2023年8月增加了利用大型语言模型（LLM）来提高OSS- Fuzz中模糊覆盖率的能力，并表示该漏洞可能在代码库中存在了20年，而且在现有的由人类编写的模糊目标中是无法发现的。此外，他们还指出，使用AI生成模糊测试目标已经提高了272个C/C++项目的代码覆盖率，新增了超过370,000行新代码。  
  
谷歌解释说，这样的漏洞之所以能够长时间未被发现，一个原因是线覆盖率并不能保证函数没有漏洞。代码覆盖率作为一项指标，无法衡量所有可能的代码路径和状态，不同的标志和配置可能会触发不同的行为，从而暴露出不同的漏洞。这些人工智能辅助的漏洞发现也是可能的，因为LLMs被证明擅长模仿开发人员的模糊工作流程，从而允许更多的自动化。正如谷歌之前就提到过，其基于LLM的框架Big Sleep帮助发现SQLite开源数据库引擎中的一个零日漏洞。  
## C++代码安全性大幅提升  
  
与此同时，谷歌一直在努力将自己的代码库转换为内存安全语言，如Rust，同时还对现有的C++项目（包括Chrome）中的空间内存安全漏洞（当代码可能访问超出其预定范围的内存时）进行改造。其中包括迁移到安全缓冲区和启用强化的libc ++，后者将边界检查添加到标准的 C ++数据结构中，以消除大量的空间安全缺陷。它进一步指出，纳入这一变化所产生的间接费用很小（即平均0.30%的绩效影响）。  
  
谷歌表示，由开源贡献者最近添加的“hardened libc++”引入了一系列安全检查，旨在捕获生产中的越界访问等漏洞。虽然C++不会完全成为内存安全的语言，但这些改进降低了风险，从而使得软件更加可靠和安全。  
  
具体来说，hardened libc++通过为标准C++数据结构添加边界检查来消除一大类空间安全漏洞。例如，hardened libc++确保对std::vector的每个元素的访问都保持在其分配的边界内，防止尝试读取或写入超出有效内存区域的尝试。同样，hardened libc++在允许访问之前检查std::optional是否为空，防止访问未初始化的内存。这种改进对于提高C++代码的安全性和可靠性具有重要意义。  
  
参考原文：https://thehackernews.com/2024/11/googles-ai-powered-oss-fuzz-tool-finds.html  
  
> **文章来源 ：IT之家、安全圈******  
  
  
**精彩推荐**  
  
  
  
  
# 乘风破浪|华盟信安线下网络安全就业班招生中！  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575781&idx=2&sn=ea0334807d87faa0c2b30770b0fa710d&chksm=83bdf641b4ca7f5774129396e8e916645b7aa7e2e2744984d724ca0019e913b491107e1d6e29&scene=21#wechat_redirect)  
  
  
# 【Web精英班·开班】HW加油站，快来充电！  
  
  
‍[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650594891&idx=1&sn=b2c5659bb6bce6703f282e8acce3d7cb&chksm=83bdbbafb4ca32b9044716aec713576156968a5753fd3a3d6913951a8e2a7e968715adea1ddc&scene=21#wechat_redirect)  
  
  
‍  
# 始于猎艳，终于诈骗！带你了解“约炮”APP  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575222&idx=1&sn=ce9ab9d633804f2a0862f1771172c26a&chksm=83bdf492b4ca7d843d508982b4550e289055c3181708d9f02bf3c797821cc1d0d8652a0d5535&scene=21#wechat_redirect)  
  
**‍**  
  
