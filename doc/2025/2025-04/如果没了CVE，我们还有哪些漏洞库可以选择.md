#  如果没了CVE，我们还有哪些漏洞库可以选择   
 sec0nd安全   2025-04-18 04:27  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/qTcIBaTRMWdjcGWCVUAKtpd05lBUJo0eJ4bg9ujlbhoFeMUcSBFia6tzfs0GPK3RRcLC8vysusEFvqicJ0VGicMtA/640 "")  
  
点击上方  
蓝字  
关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibV6vqVQpnKD9eLpCQAf69UFrxu8NdzsuFfBDKuKia0X9xJm2mFicP6xnfvpUSafPWB448zx1apYe9Tt76TgsJ12Q/640 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JmssGpneVHK2aNAIsS7yQ1icFsQMnHqJhsY5gGWBhGwlDF4mVgbdT6WG0ialZ1GdFOYblVeBCAQzTQhYbBFS7Wog/640 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vgBONCKBxQ9fejl98shElqstWkLcgKRY19YkXtadGoOIicFdFmlic8W8lNhs4zOfYFyQg1libTATLPg/640?wx_fmt=png&from=appmsg "")  
  
美国非营利研发组织 MITRE 在 2025 年 4 月宣布，其与美国国土安全部（DHS）签订的 CVE 数据库维护合同于 4 月 16 日午夜到期，DHS 拒绝续约。运行长达 25 年的 CVE 项目，面临着随时可能终止的危机。虽然美国网络安全与基础设施安全局（CISA）表示正在紧急采取措施减轻影响，维护 CVE 服务，但 CVE 未来的不确定性仍让业界忧心忡忡。  
  
CVE 作为全球网络安全漏洞信息共享的重要平台，长期以来为安全行业提供了标准化的漏洞标识和信息描述。一旦其正常运作受到影响，从国家层面的漏洞数据，到各类安全工具厂商、事件响应行动以及关键基础设施的安全防护，都可能面临混乱和挑战。不过，除了 CVE 之外，我们其实还有众多优秀的漏洞库可供选择。  
  
  
  
NVD：美国国家漏洞数据库  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vgBONCKBxQ9fejl98shElqWicXvqY32WyvyXibiat8qicnDJFSp7j9oII9BhuqXvP4M4mfQVhicstVYTg/640?wx_fmt=png&from=appmsg "")  
  
NVD（National Vulnerability Database）由美国国家标准与技术研究所（NIST）发布并维护。它与 CVE 有着紧密的联系，很多 CVE 漏洞在 NVD 中能找到更为详尽的分析。NVD 运用安全内容自动化协议（SCAP）来呈现数据，这使得它在漏洞管理、安全测量以及合规性自动化方面表现出色。这里不仅有安全检查表参考数据库，还涵盖了安全相关的软件缺陷、错误配置、产品名称及影响范围等丰富信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640 "")  
  
地址：https://nvd.nist.gov/  
  
  
CVE Details  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vgBONCKBxQ9fejl98shElqpzibDwet9P99OzwrD2JtPZHpN61xXhFOqhxTdGBkQHAJ7GN9ONl8aAw/640?wx_fmt=png&from=appmsg "")  
  
CVE Details 专注于 CVE 信息的查询，是一个非常实用的平台。在这里，用户能够浏览不同供应商、产品及其对应的版本信息，并查看与之相关的 CVE 条目和漏洞详情。同时，它还提供关于供应商、产品和产品版本的统计信息。例如，通过这些统计，企业可以了解到某个供应商在一段时间内产品出现漏洞的频率，以及哪些版本更容易遭受攻击，这对于企业在采购产品和进行安全规划时，有着重要的参考价值。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640 "")  
  
地址：https://www.cvedetails.com/  
  
  
Exploit-DB（Exploit Database）  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vgBONCKBxQ9fejl98shElqLJIp5bQGkU198r0jqhaAp1slibpSe4fWSslrr9FkYrgGc7YbLWBJhog/640?wx_fmt=png&from=appmsg "")  
  
Exploit Database 由 Offensive Security 维护，这是一家专注于信息安全培训的公司，提供多种信息安全认证以及高端渗透测试服务。而 EDB 本身是一个非盈利项目，免费向公众开放。它作为漏洞利用和 POC（概念验证）验证数据库，为安全研究人员和渗透测试人员提供了海量的实际漏洞利用代码示例。这些示例覆盖了 Web、网络、软件等多个领域，对于深入理解漏洞原理以及开展安全测试工作具有不可替代的作用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640 "")  
  
地址：https://www.exploit-db.com/  
  
  
OSV：开源项目漏洞数据库  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vgBONCKBxQ9fejl98shElqPR0tcFNEk5HxjLRAR9SdgOYPvH3DveSD6kpNkXZYZTtEu7HAiaNK3EA/640?wx_fmt=png&from=appmsg "")  
  
OSV 是 Google 推出的专门针对开源项目的漏洞数据库和分类基础设施。随着开源软件在各行业的广泛应用，开源项目的安全变得愈发重要。OSV 能够及时收集、整理开源项目中的漏洞信息，并给出相应的修复建议和指导。这对于保障基于开源软件构建的系统的安全性意义重大，帮助开发者和用户更好地应对开源项目中的漏洞问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640 "")  
  
地址：https://osv.dev/  
  
  
CNVD：中国国家漏洞数据库  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vgBONCKBxQ9fejl98shElq9PqTatlWgPeNu3PxSSl00ebWIpicGKdhBPmLibF4zQ4MElFLfGdxjZoA/640?wx_fmt=png&from=appmsg "")  
  
CNVD 由中国国家计算机网络应急技术处理协调中心（CNCERT）联合国内重要信息系统单位、基础电信运营商、网络安全厂商、软件厂商和科研机构共同建立。它重点关注国内出现的安全漏洞，对于国内企业和机构而言，在处理涉及国内环境和特定应用的漏洞时，CNVD 提供的信息更具针对性和实用性，能更好地满足国内安全防护的需求。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640 "")  
  
地址：http://www.cnvd.org.cn/  
  
  
CNNVD：中国信息安全测评中心漏洞库  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vgBONCKBxQ9fejl98shElq7tbEIOOokAEAhBwReO0IusNuhqSzxNgibBJ7UKMZf86qqEXzxOAt1Xg/640?wx_fmt=png&from=appmsg "")  
  
CNNVD 是中国信息安全测评中心在国家专项经费支持下，负责建设运维的国家级信息安全漏洞数据管理平台。其目的在于为我国的信息安全保障工作提供坚实有力的支持，通过对漏洞的深度分析和风险评估，助力相关部门和企业及时察觉并解决安全隐患。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640 "")  
  
地址：http://www.cnnvd.org.cn/  
  
  
AVD：阿里云漏洞库  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vgBONCKBxQ9fejl98shElqCmSHznoZpSu6bwo1WN2JxcfWJP1KgW87euzPZLG3eJia16emTtCzszQ/640?wx_fmt=png&from=appmsg "")  
  
AVD 作为阿里云漏洞库，在及时响应与收敛云上高危漏洞方面表现卓越，为使用阿里云服务的客户提供了可运营的漏洞管理功能。该漏洞库不仅涵盖了 CVE 漏洞库中的部分信息，还设有非 CVE 漏洞库以及专门的高危漏洞库。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QkjvmbC1CD0zJ9hBlrElSv4ZqETGn3otgH8VHW1QuoOec3JMAbUyr0iaurJy4DPHBwUsDXiadJ3aha4CvJwyYVew/640 "")  
  
地址：https://avd.aliyun.com/  
  
[反序列化漏洞原理剖析：从攻击到防御](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485940&idx=1&sn=2f88a93a08b27fbe28ca59fe07c58f2a&scene=21#wechat_redirect)  
  
  
[2025-04-09](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485940&idx=1&sn=2f88a93a08b27fbe28ca59fe07c58f2a&scene=21#wechat_redirect)  
  
  
[ ](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485940&idx=1&sn=2f88a93a08b27fbe28ca59fe07c58f2a&scene=21#wechat_redirect)  
  
  
[俄罗斯 0day 买家提供创纪录的 4,000,000 美元电报漏洞利用赏金](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485871&idx=1&sn=62e93e80759c463c007353af2431b080&scene=21#wechat_redirect)  
  
  
[2025-03-24](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485871&idx=1&sn=62e93e80759c463c007353af2431b080&scene=21#wechat_redirect)  
  
  
[ ](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485871&idx=1&sn=62e93e80759c463c007353af2431b080&scene=21#wechat_redirect)  
  
  
[生成式 AI 有望更快地对漏洞进行分类](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485747&idx=1&sn=f1cf8fefe8dd1c08140c5a0126f9e7a7&scene=21#wechat_redirect)  
  
  
[2025-03-05](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485747&idx=1&sn=f1cf8fefe8dd1c08140c5a0126f9e7a7&scene=21#wechat_redirect)  
  
  
[ ](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485747&idx=1&sn=f1cf8fefe8dd1c08140c5a0126f9e7a7&scene=21#wechat_redirect)  
  
  
[黑客在 Pwn2Own Automotive 2025 第一天利用了 16 个0day漏洞](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485575&idx=1&sn=d70e6f03b4c4364b95475edb267f52e3&scene=21#wechat_redirect)  
  
  
[2025-01-24](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485575&idx=1&sn=d70e6f03b4c4364b95475edb267f52e3&scene=21#wechat_redirect)  
  
  
[ ](https://mp.weixin.qq.com/s?__biz=Mzg3NTY0MjIwNg==&mid=2247485575&idx=1&sn=d70e6f03b4c4364b95475edb267f52e3&scene=21#wechat_redirect)  
  
  
**喜欢此文的话，可以点赞、转发、在看 一键三连哦！**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jDxr6RVaB7vglcuxSMkmalibicmpOSAop2ebtW81WD17lIoywzweqOrtD2C7MiaU003Cdo8F8ZpWTqvY50VeDja9w/640?wx_fmt=png&from=appmsg "")  
  
  
  
