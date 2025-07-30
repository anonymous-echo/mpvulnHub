> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547158&idx=2&sn=6590b74b0b9a26bac77f815dfde586e6

#  半导体巨头AMD新型漏洞影响多款CPU，计时攻击可导致数据泄露  
 安小圈   2025-07-12 00:45  
  
**安小圈**  
  
  
第707期  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbMibAJyoSBZCq6jsdVYUCCqPibdfdEiaCaXEodT6ia9PvtQqGLQ9eKXIW1WqsFC0pHP4B8mmcjFWV3reg/640?wx_fmt=jpeg "")  
  
  
半导体巨头AMD近日警告称，其多款芯片组存在新型漏洞，可能导致信息泄露风险。这种被称为"瞬态调度攻击"（Transient Scheduler Attacks，TSA）的攻击方式，会通过CPU在特定微架构条件下的指令执行时序，形成推测性侧信道漏洞。  
  
  
  
**Part01**  
  
## 漏洞详情与CVE编号  
  
  
AMD在安全公告中表示："在某些情况下，攻击者可能利用这种时序信息推断其他上下文的数据，从而导致信息泄露。"这些漏洞是微软与苏黎世联邦理工学院研究人员在研究现代CPU对抗Meltdown和Foreshadow等推测执行攻击时发现的，他们通过虚拟机、内核和进程等安全域之间的隔离压力测试发现了这些问题。  
  
  
2024年6月经过负责任披露后，这些漏洞被分配了以下CVE编号：  
  
  
1. CVE-2024-36350（CVSS评分：5.6）- 某些AMD处理器中的瞬态执行漏洞可能允许攻击者推断先前存储的数据，可能导致特权信息泄露  
  
  
2. CVE-2024-36357（CVSS评分：5.6）- 某些AMD处理器中的瞬态执行漏洞可能允许攻击者推断L1D缓存中的数据，可能导致跨特权边界的敏感信息泄露  
  
  
3. CVE-2024-36348（CVSS评分：3.8）- 某些AMD处理器中的瞬态执行漏洞即使用户模式指令防护(UMIP)功能已启用，仍可能允许用户进程推测性地推断控制寄存器，可能导致信息泄露  
  
  
4. CVE-2024-36349（CVSS评分：3.8）- 某些AMD处理器中的瞬态执行漏洞即使在禁用读取的情况下，仍可能允许用户进程推断TSC_AUX值，可能导致信息泄露  
  
  
  
**Part02**  
  
## 受影响处理器型号与修复措施  
  
  
AMD将TSA描述为影响其CPU的"新型推测性侧信道漏洞"，并已为受影响处理器发布微码更新，涉及产品包括：  
  
- 第三代AMD EPYC处理器  
  
- 第四代AMD EPYC处理器  
  
- AMD Instinct MI300A  
  
- AMD Ryzen 5000系列桌面处理器  
  
- 带Radeon显卡的AMD Ryzen 5000系列桌面处理器  
  
- AMD Ryzen 7000系列桌面处理器  
  
- 带Radeon显卡的AMD Ryzen 8000系列处理器  
  
- AMD Ryzen Threadripper PRO 7000 WX系列处理器  
  
- 带Radeon显卡的AMD Ryzen 6000系列处理器  
  
- 带Radeon显卡的AMD Ryzen 7035系列处理器  
  
- 带Radeon显卡的AMD Ryzen 5000系列处理器  
  
- 带Radeon显卡的AMD Ryzen 7000系列处理器  
  
- 带Radeon显卡的AMD Ryzen 7040系列处理器  
  
- 带Radeon显卡的AMD Ryzen 8040系列移动处理器  
  
- AMD Ryzen 7000系列移动处理器  
  
- AMD EPYC Embedded 7003  
  
- AMD EPYC Embedded 8004  
  
- AMD EPYC Embedded 9004  
  
- AMD EPYC Embedded 97X4  
  
- AMD Ryzen Embedded 5000  
  
- AMD Ryzen Embedded 7000  
  
- AMD Ryzen Embedded V3000  
  
**Part03**  
  
## 技术原理与攻击变种  
  
  
AMD指出，从内存读取数据的指令可能会出现"虚假完成"现象——当CPU硬件预期加载指令会快速完成，但存在某些条件阻止其完成时就会发生这种情况：  
  
  
在这种情况下，依赖操作可能会在检测到虚假完成之前就被调度执行。由于加载实际上并未完成，与该加载相关的数据被视为无效。加载操作稍后将重新执行以成功完成，所有依赖操作将在有效数据就绪时重新执行。  
  
  
与预测性存储转发等其他推测行为不同，遭遇虚假完成的加载不会导致最终的流水线刷新。虽然与虚假完成相关的无效数据可能会被转发给依赖操作，但使用这些数据的加载和存储指令不会尝试获取数据或更新任何缓存或TLB状态。因此，无法使用标准瞬态侧信道方法推断这些无效数据的值。  
  
  
但在受TSA影响的处理器中，这些无效数据可能会以攻击者可检测到的方式影响CPU执行其他指令的时序。  
  
  
AMD表示根据虚假完成相关无效数据的来源，已识别出TSA-L1和TSA-SQ两种变体：分别源自L1数据缓存或CPU存储队列。  
  
  
**Part04**  
  
## 潜在影响与利用条件  
  
  
在最坏情况下，利用TSA-L1或TSA-SQ漏洞的成功攻击可能导致：  
  
  
操作系统内核向用户应用程序的信息泄露  
  
虚拟机监控程序向客户虚拟机的信息泄露  
  
两个用户应用程序之间的信息泄露  
  
  
TSA-L1是由L1缓存使用微标签进行数据缓存查找时的错误引起的，而TSA-SQ漏洞则发生在所需数据尚不可用时，加载指令错误地从CPU存储队列检索数据的情况下。在这两种情况下，攻击者都可以推断出L1缓存中存在的任何数据或被旧存储使用的数据，即使这些数据是在不同上下文中执行的。  
  
  
不过，利用这些漏洞需要攻击者先获得对机器的恶意访问权限，并具备运行任意代码的能力，无法通过恶意网站进行利用。AMD强调："利用TSA所需的条件通常是暂时的，因为CPU检测到虚假完成后，微标签和存储队列都会更新。因此，要可靠地窃取数据，攻击者通常需要能够多次调用受害者以重复制造虚假完成条件。当攻击者和受害者之间存在现有通信路径（如应用程序与操作系统内核之间）时，这种情况最有可能实现。"  
  
  
  
  
参考来源：  
  
AMD Warns of New Transient Scheduler Attacks Impacting a Wide Range of CPUs  
  
https://thehackernews.com/2025/07/amd-warns-of-new-transient-scheduler.html  
  
  
END  
  
  
  
**【以上内容**  
**来源于：FreeBuf】**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeeR4VInT56J0KCLD3HkiaRxjMLLV6rricOadHohJB1sOtPT02fETAxr4g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/0YKrGhCM6DbI5sicoDspb3HUwMHQe6dGezfswja0iaLicSyzCoK5KITRFqkPyKJibbhkNOlZ3VpQVxZJcfKQvwqNLg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
[微软紧急修复高危蠕虫级RCE漏洞，威胁全网Windows系统](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547132&idx=1&sn=cd484270f0cd9ed5dc17fdeafb2e76dd&scene=21#wechat_redirect)  
  
  
- [【HVV】护网系列 威胁情报共享7.9](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547108&idx=1&sn=01f68c9cc76760e8e5e0615df3b54c6c&scene=21#wechat_redirect)  
  
  
- [25HVVRT钓鱼样本，警惕！多家单位已中...](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547104&idx=1&sn=8e06fcde039b325eedcb2eac8ba04f95&scene=21#wechat_redirect)  
  
  
- [【HVV】护网系列 威胁情报共享7.8](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547054&idx=1&sn=014e2f4baedfea584d880c612e51b884&scene=21#wechat_redirect)  
  
  
- [【更！】25HVV热点攻击漏洞含0day，各单位自查...](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547053&idx=1&sn=ab425df27b630dfa1c1d59759bf1ad37&scene=21#wechat_redirect)  
  
  
- [【HVV】护网系列 威胁情报共享7.7](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247547048&idx=1&sn=d943617032f197fb6cb70fff9f8eb3d2&scene=21#wechat_redirect)  
  
  
- [25HVV最新0day更新，各单位自查...](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546998&idx=1&sn=c3077c2a50dfec80de8f9e21b507ae53&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=1&sn=2f16da5665014b4c07bcbd53e3d1c03e&scene=21#wechat_redirect)  
- [【HW】8个因护网被开除的网安人](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=1&sn=2f16da5665014b4c07bcbd53e3d1c03e&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=2&sn=e9578e62a475ac5c46b95ac81066d2a7&scene=21#wechat_redirect)  
- [HW应急溯源：50个高级命令实战指南](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546898&idx=2&sn=e9578e62a475ac5c46b95ac81066d2a7&scene=21#wechat_redirect)  
  
  
- [震惊全球！中国团队攻破RSA加密！RSA加密告急？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546856&idx=1&sn=11b36f6fabde860e889e4ac2f4797bba&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbOugegrykhydnkHibcSWjpibTBZoK6jjGxJiax1BcwwctpA5SBric9aPdQFXsxFnn4LQJWdkYwbtPN0gg/640?wx_fmt=jpeg "")  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546815&idx=1&sn=99a4f3228f322ef92c93d23cee01f071&scene=21#wechat_redirect)  
- [2025年【护网】攻防演练时间已定！](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546815&idx=1&sn=99a4f3228f322ef92c93d23cee01f071&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546578&idx=1&sn=87cdf84e6fd7d35986b29acd90954c65&scene=21#wechat_redirect)  
  
[突发！小红书惊现后门......](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546578&idx=1&sn=87cdf84e6fd7d35986b29acd90954c65&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbPwt82pEdc2YwCDz6n3H3c2C0ibcMl4Tea8hM59iaZoR1FDMTCUswDiclc1icLoSywpkWbdqyb6uBNcnA/640?wx_fmt=jpeg "")  
- [2025年“净网”“护网”专项工作部署会在京召开，看看都说了哪些与你我相关的关键内容？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546673&idx=1&sn=53fe0365785465d4ff6193a9ca639119&scene=21#wechat_redirect)  
  
  
- # 护网即将来临，这场网安盛会带给了我们打工人什么......  
  
- [护网在即，企业还有什么新思路可以应对吗？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546698&idx=1&sn=55ab4ac8dffb5f7ccf02a4f759537acf&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbPwt82pEdc2YwCDz6n3H3c2Noz3ibYqNZ52uicBtuVVlFRg6vSuF8YFjPvCVma1ADrT1ViaKVE9URNOA/640?wx_fmt=jpeg "")  
- [HW必备：50个应急响应常用命令速查手册一（实战收藏）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546304&idx=2&sn=45ef99e528ded7ff2e65e4d70e6d5181&scene=21#wechat_redirect)  
  
  
- [HW必备：50个应急响应常用命令速查手册二（实战收藏）](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546327&idx=2&sn=cf1ebbd2b511524ec965a3672b6fc3dd&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546530&idx=1&sn=4a2820b60102e538e87c956375f6fcdb&scene=21#wechat_redirect)  
- [网安同行们，你们焦虑了吗？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546530&idx=1&sn=4a2820b60102e538e87c956375f6fcdb&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247546466&idx=1&sn=a9d55d0b430dbf61dc219fd71ce25ae1&scene=21#wechat_redirect)  
- # 网安公司最后那点体面，还剩下多少？  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545577&idx=1&sn=76a4dbd28d9c0e006b7790d89c2b1354&scene=21#wechat_redirect)  
- [2024年网安上市公司营收、毛利、净利润排行](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545577&idx=1&sn=76a4dbd28d9c0e006b7790d89c2b1354&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545311&idx=2&sn=bb8ff7cd42079bae40ab0a2e05ff37c1&scene=21#wechat_redirect)  
- [突发！数万台 Windows 蓝屏。。。。广联达。。。惹的祸。。。](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545311&idx=2&sn=bb8ff7cd42079bae40ab0a2e05ff37c1&scene=21#wechat_redirect)  
  
  
#   
- # 权威解答 | 国家网信办就：【数据出境】安全管理相关问题进行答复  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247539649&idx=1&sn=8858b449c89d21240e1f522e92be4fbd&scene=21#wechat_redirect)  
- # 全国首位！上海通过数据出境安全评估91个，合同备案443个  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544405&idx=2&sn=a961d43ca4a9ed667fccbbab758d9196&scene=21#wechat_redirect)  
- # 沈传宁：落实《网络数据安全管理条例》，提升全员数据安全意识  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545156&idx=1&sn=ee5292e9838b2a2112a94a9c7c683925&scene=21#wechat_redirect)  
  
- [频繁跳槽，只为投毒](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545156&idx=1&sn=ee5292e9838b2a2112a94a9c7c683925&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545017&idx=1&sn=b513c15f91d5de7a8fa33c4b3725706a&scene=21#wechat_redirect)  
- [【高危漏洞】Windows 11：300毫秒即可提权至管理员](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247545017&idx=1&sn=b513c15f91d5de7a8fa33c4b3725706a&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544601&idx=1&sn=e230574b0535e6005b830d086cdcf867&scene=21#wechat_redirect)  
- [针对网安一哥专门的钓鱼网站](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544601&idx=1&sn=e230574b0535e6005b830d086cdcf867&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=1&sn=06311aa3f8aeba492f83224c652fe4a1&scene=21#wechat_redirect)  
  
- [为什么【驻场】网络安全服务已成为大多数网络安全厂商乙方不愿再触碰的逆鳞？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=1&sn=06311aa3f8aeba492f83224c652fe4a1&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbOYPldtHVUmKQJ2WtL12GUnHRyzBiaKosLNicTZ2QkDFSRPUha2Eiaqk8R5fPdXc75zxprkTRB0ib5hUw/640?wx_fmt=jpeg "")  
- [HW流程以及岗位职责](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247544347&idx=3&sn=97e6083dbfbdd896680e24770a10d319&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247543989&idx=1&sn=2821b91efdd626e1a38ec6b2b439186b&scene=21#wechat_redirect)  
  
- # 网络安全【重保】| 实战指南：企业如何应对国家级护网行动？  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542929&idx=1&sn=8cf6f15ddca44e343a494eea0fa619b2&scene=21#wechat_redirect)  
- **DeepSeek安全：AI网络安全评估与防护策略**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542701&idx=1&sn=567674aa12d861c3561d453268badb91&scene=21#wechat_redirect)  
- **虚拟机逃逸！VMware【高危漏洞】正被积极利用，国内公网暴露面最大******  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542458&idx=1&sn=d81d049331d175a2176f0978d7f032a8&scene=21#wechat_redirect)  
- **挖矿病毒【应急响应】处置手册******  
  
****- **用Deepseek实现Web渗透自动化**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247542225&idx=2&sn=244a465fab183f4fa91a284b92a920e6&scene=21#wechat_redirect)  
- **【风险】DeepSeek等大模型私有化服务器部署近九成在“裸奔”，已知漏洞赶紧处理！**  
  
****- **关于各大网安厂商推广「DeepSeek一体机」现象的深度分析**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247541264&idx=1&sn=887bf392ba73e7c2c833a410e7168818&scene=21#wechat_redirect)  
- [Deepseek真的能搞定【安全运营】？](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247541264&idx=1&sn=887bf392ba73e7c2c833a410e7168818&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540432&idx=1&sn=b9e7e6103e86b9966f29d7eacf8e3d1e&scene=21#wechat_redirect)  
- **【热点】哪些网络安全厂商接入了DeepSeek？**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540206&idx=2&sn=300737ad84f684e622fdde03da0fc1a7&scene=21#wechat_redirect)  
- **【2025】常见的网络安全服务大全（汇总详解）**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MDg0ODg1NQ==&mid=2247540343&idx=1&sn=59d6f592f71a7f1e3a18fd082aa3de40&scene=21#wechat_redirect)  
- **AI 安全 |《人工智能安全标准体系(V1.0)》(征求意见稿)，附下载**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMbfUY7RtO1t6ZAxjoibZoZ8DSVPU0yI9v2nXpiat0oN8eLia5jiaoWOhlib5GiaPWQJeCsUmShI4QOqaGg/640?wx_fmt=png "")  
- **2025年 · 网络威胁趋势【预测】**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbM09kF5tXEb8PRXicFibPic4un6rwDI2CBUxrVaDINuM8ChyotgWiag4icErAHniaYNYiccQiaVkyyJUTX13w/640?wx_fmt=jpeg "")  
- **【实操】常见的安全事件及应急响应处**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbMASB7RibZ1nezrias4SvtcqzjvsJJPXhFiceJPEoVHVLhI2Soolaf8OhWQOVafycOibiaclJkT7NgG4Nw/640?wx_fmt=jpeg "")  
- **2024 网络安全人才实战能力白皮书安全测试评估篇**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbMSrNYPzeZSs4X316kGV7UeOsnl5ayrQXc0wPVutL1dQXg7BugT7vAe8qkpfszTrlhUAq4DQZFaVA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BWicoRISLtbP7Bh21K85KEkXX7ibWmLdM2eafpPicoTqk37LEVMUKD1JuAic4FF4KB7jP4oFTricyMwvj5VUZZ824ww/640?wx_fmt=gif "")  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BWicoRISLtbNzlia8CP45sjgLJgia5Y22hx8khBeShnAzCPwsfqeIVKkpFDhUoMUWMicq6toR2TSUmgBpgzZQHEAHw/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BWicoRISLtbPFKyibwduMibC35MsIhibgZEAibwSyVRz7FKt3xa1UK61fXXCCUKllCXFrLdnBqcmgiaKeSxGrWT0RtYw/640?wx_fmt=png "")  
  
