#  IoT智能设备产品「发售前」安全检验：关乎品牌声誉的漏洞之战   
 斗象科技   2025-04-25 05:59  
  
![](https://mmecoa.qpic.cn/sz_mmecoa_jpg/hrWzJ3hmo1Z5jfbE0AiafcJbDa7vb5UeXLQ5EUmjEVDWd2E3V9DdWT8LfrAYtiasYLpl3LffVFcLWtftUvJMFkmA/640?wx_fmt=jpeg "")  
  
在智能设备安全事件频发的今天，欧盟2024年新规规定所有联网设备必须提供5年的免费安全更新，我国《物联网基础安全 物联网平台安全分级分类管理评估方法》（YD/T 6039-2024）在今年2月正式实施，**合规与网络安全性已经成为智能产品的重要指标之一**。  
  
   
  
2024年12月，距某全球500强综合性智能电子设备集团（以下简称：该集团）的新一代智能摄像头全球上市还有3个月，为预防产品发布后出现安全漏洞损害品牌声誉，对市场推广造成阻碍，该集团带着对产品安全的高度重视与责任感找了斗象科技。  
  
  
★  
  
  
斗象作为该集团的长期安全合作伙伴，  
**创新融合了漏洞盒子智能设备领域白帽专家众测与星耀专家精测**的优势，展示了如何通过严格的预上市测试，为品牌奠定稳固的安全基石。  
  
![](https://mmecoa.qpic.cn/sz_mmecoa_png/hrWzJ3hmo1Z5jfbE0AiafcJbDa7vb5UeXVwInhGibejqxqCChdudHegiaeWOIRZwGCQROCUibOwHwGGjGGpHzBzo7Q/640?wx_fmt=png "")  
  
  
  
智能产品融合了传感器、通信模块、嵌入式系统等多种技术，使其具有感知、计算、通信和决策等智能化功能，  
**但这也使得其风险漏洞广泛存在于硬件芯片、通信协议、设备固件、云端服务等多个环节，相较于传统软硬件呈现出“多点开花”的特点，任何一个环节的疏漏都可能成为攻击入口****。**同时，该智能摄像头需对接众多智能家居或安防设备与云平台，一旦在上市后出现安全问题，将引发生态链索赔与信任危机。因此，该集团急需一套上市前全维度的安全检测方案，并严格保密产品架构信息。  
  
   
  
**为帮助企业在产品上市全方位排查安全风险，同时考虑到智能摄像头设备芯片型号、产品架构等敏感信息上市前的保密需求，星耀实验室制定了层层拆解的多维检测计划****。**  
实验室专家先将摄像头拆解为多个组成单元，对硬件、固件等进行评估。采用逻辑分析仪、芯片侧信道测试工具、协议分析仪和调试工具等专业设备进行测试，并结合自主研发的漏洞检测软件，实现从芯片级到系统级的全面测试。  
  
![](https://mmecoa.qpic.cn/sz_mmecoa_png/hrWzJ3hmo1Z5jfbE0AiafcJbDa7vb5UeXNyLibian4th5ItiaadQKIyDFibwzFnJnmLbky9jyc4icVagDiboEktt0X0lA/640?wx_fmt=png "")  
  
  
★  
  
  
同时实验室搭建了一个虚拟测试环境以及实机验证环境，成功实现了智能摄像头的真实物理设备上线。通过这一平台，将**系统应用、设备网络通信、APP应用**等待测评项发布至漏洞盒子众测平台，克服传统IoT设备难以实施众测的难题，**从15W+经过认证的可信白帽专家中挑选领域白帽专家展开测评**，确保智能摄像头众测项目的机密性和效率。  
  
![](https://mmecoa.qpic.cn/sz_mmecoa_png/hrWzJ3hmo1Z5jfbE0AiafcJbDa7vb5UeXCSfPHOHWn0ms0bxvGITsicd0mFpzt9GIoYRHEETJETZPrT5tr8rQrnQ/640?wx_fmt=png "")  
  
![](https://mmecoa.qpic.cn/sz_mmecoa_png/hrWzJ3hmo1Z5jfbE0AiafcJbDa7vb5UeXBSBjiaUXEyEhRodlS4SIVLE25kXfhTyvRIk8rBejMgHZ1XM6PvAqEGA/640?wx_fmt=png "")  
  
  
  
斗象星耀专家团队与领域白帽专家（以下简称：测试专家）通过**硬件风险检测、二进制漏洞挖掘、协议分析**等手段，对该智能摄像头从硬件、软件到通信的层层漏洞风险排查，帮助企业在上市前排查到了两处潜在风险巨大的漏洞。  
  
  
  
**Web服务接口端远程命令执行高危漏洞**  
  
  
在设备应用测试中，测试专家通过逆向分析应用代码和劫持网络请求的方式对该摄像头进行分析时，发现了其Web服务接口存在两个严重的远程命令执行漏洞。  
**该漏洞允许攻击者在未授权的情况，通过构造特定的POST请求，将恶意命令注入到设备的系统调用中，进行植入恶意代码或篡改获取视频数据等恶意活动，或进一步攻击局域网内其他设备，为企业带来用户隐私泄露和大规模网络攻击发生的威胁**  
**。**  
  
  
  
**Secure Boot安全启动机制两个关联漏洞**  
  
  
在对该摄像头的Secure Boot安全启动机制测试时，发现了其存在**“载入解密固件、绕过固件签名”**两个关联漏洞，这一漏洞缺陷使得攻击者可以控制设备加载经过篡改的kernel镜像，  
**获取主要程序app的明文数据，并进一步非法操作窃取用户实时影像，甚至将设备作为跳板入侵同一局域网内其他智能设备，潜在风险巨大****。**  
  
   
  
上述高危漏洞若在上市后暴露，受智能设备 “一次性部署” 特性制约，修复将难以落实。此外，测试专家还发现 **Web 后台临时密码缺陷、高危隐藏调试指令、OTA 任意降级及设备控制请求重放攻击**等隐患，全方位定位风险，为企业成功规避了上市后的安全危机。  
  
![](https://mmecoa.qpic.cn/sz_mmecoa_png/hrWzJ3hmo1Z5jfbE0AiafcJbDa7vb5UeXia3DL5FcBMia2iaqLObu5v2QmYW7ZYoPDeAruhBRvSGY7eeyJanax99rQ/640?wx_fmt=png "")  
  
  
  
针对上述漏洞和风险威胁，斗象出具了包含漏洞原理、影响范围及修复方案的专业报告，协助客户全面修复智能摄像头存在的风险漏洞，在产品上市前从源头防范潜在威胁的发生；并进一步基于此次测评暴露出的系统性问题，在流程和管理层面为企业提供深度咨询与服务，协助全面完善产品的安全生产机制。  
  
  
  
**针对Web端的远程命令执行高危漏洞**  
  
  
加强接口管理，对用户输入严格执行格式验证，防范恶意代码注入，全面阻断远程命令的执行风险；  
  
  
**针对Secure Boot的关联漏洞**  
  
  
关闭物理调试接口或至少关闭接口的输入，并多管齐下强化安全启动和固件合法校验，彻底封堵 Secure Boot 漏洞；  
  
  
**风险点加固**  
  
  
通过使用安全的加密算法、移除隐藏的后门指令、强化授权控制、强制检测固件版本等措施进行了全面的修复加固。  
  
  
  
**产品安全生产机制完善**  
  
  
**在流程层面**：斗象专家团队安全测试深度融入产品研发全生命周期，协助集团加强供应商安全准入标准与应急响应机制，提升产品生产的安全性；  
  
**在管理层面**：定期开展合作安全培训，通过内部培训提升全员安全意识，提前规划合规认证，主动披露安全信息，塑造企业安全品牌形象。  
  
  
![](https://mmecoa.qpic.cn/sz_mmecoa_png/hrWzJ3hmo1Z5jfbE0AiafcJbDa7vb5UeXekcVpld8h6ovoR5ZOaBQbSFSHmU1SO5aaxhY2mkroeibNPN4NPf7icaw/640?wx_fmt=png "")  
  
  
![](https://mmecoa.qpic.cn/sz_mmecoa_gif/hrWzJ3hmo1ZBj5APK1yyWhYv2prpsH25M7ElOJoaYFZ21EzA2w2Lic8ThUS1vs3aC0ahgz7upAQIldFCzIp5vtw/640?wx_fmt=gif "")  
[](https://mp.weixin.qq.com/s?__biz=MzU0MDI1MjUxMg==&mid=2247533159&idx=1&sn=bb60977dc7be532f0fa408245763d640&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzU0MDI1MjUxMg==&mid=2247532773&idx=1&sn=a5deae6760a95200916134dd222d5a05&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzU0MDI1MjUxMg==&mid=2247523879&idx=1&sn=dd73a9aaef6632ae8cb9236b4d486ce5&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/hrWzJ3hmo1bw4EJc1KnhFjaeYutKaQqatG61h6R3qSp9QBdKjfLHNph0rSAmsbriadeggSicC0KMxdzBEtHPOsxg/640?wx_fmt=gif&wxfrom=10005&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
