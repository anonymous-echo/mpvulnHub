#  当漏洞攻击遇上腾讯混元超能力：EdgeOne 的 Web 安全赛博决斗   
 腾讯安全   2025-04-14 09:44  
  
《腾讯云2024年DDoS与应用安全威胁趋势报告》显示，利用漏洞和应用弱点的攻击手段愈发多样化和复杂化，2024年高危漏洞攻击总量超过 17亿次，面对这一严峻挑战，我们应该如何应对？接下来将为您讲解我们的最新尝试——基于大模型的漏洞识别能力，您可以通过托管规则-深度分析功能，率先体验EdgeOne对漏洞的识别能力。  
  
  
网络安全新威胁  
  
漏洞攻击的双重挑战  
  
  
  
当前，网络安全面临着前所未有的挑战，尤其是在漏洞攻击频发的背景下。想象一下，在某个电商大促期间，黑客通过巧妙的SQL语句悄无声息地盗取用户数据，或者利用恶意脚本伪装成正常请求，在海量合法流量中发动攻击，随时可能给企业带来数据泄露和业务中断的风险。  
  
  
为了应对这些威胁，EdgeOne的Web流量攻击检测系统能够有效过滤和拦截恶意漏洞攻击流量，避免入侵和数据泄露风险。然而，随着攻击手段的不断升级，传统的防御体系面临着漏报和误报的双重困境：  
  
- 专家规则虽然能快速识别已知攻击，但对新型攻击束手无策；  
  
- 语义分析虽然准确性高，但在处理海量请求时速度较慢；  
  
- 传统机器学习虽然具备自适应能力，但对数据的依赖使其在实际应用中受到限制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdelv3p055olaj2gEf5YwaQS86VZenSk0neYVicIIRWkwEicQITJdMPQDCc2R4Wmkku8jc17GOf48usog/640?wx_fmt=png&from=appmsg "")  
  
  
在这样的背景下，如何提高检测的准确性成为了我们关注的焦点。大模型的出现为这一问题提供了新的解决方案。  
  
  
大模型在流量分析中的应用  
  
从基础知识到深度分析  
  
  
  
大模型通过预训练学习安全基础知识、HTTP流量中的代码逻辑、协议行为与攻击模式，构建多层知识关联分析，真正理解流量行为，提高检测准确性。例如，解析SQL注入时不仅识别SELECT FROM或UNION SELECT等关键词，还能判断其是否构成闭合查询、是否破坏业务逻辑。  
  
  
从下面两个例子就可以看到大模型具备对流量内容进行深度分析和理解的能力，实现从“语法合规性”到“意图危害性”理解的跃迁。  
  
  
 场景1：真假美猴王之辩，正常sql语句查询识别，避免传统静态规则匹配易误报问题。  
  
  
 传统检测：看到SQL关键词立即报警  
  
  
 LLM 侦探视角：  
  
  
 1️⃣检查请求上下文：理解语义为合法业务查询接口  
  
  
2️⃣ 行为模式分析：没有出现特殊字符构造注入  
  
  
 ⚠️ 结论：这是业务后台的正常商品查询！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdelv3p055olaj2gEf5YwaQS8Hk6OoLzjRc00rRLxlOLwp0sGZd9asrV7libbKUacticm47Sxy5lY3JvA/640?wx_fmt=png&from=appmsg "")  
  
  
 场景2：密码本的秘密，对加密内容自动解密分析，并进行意图分析，准确识别到攻击。  
  
  
 加密流量：  
  
  
 keyword=fChuc2xvb2t1cCR7SUZTfS1xJHtJRIN9Y25hbWUke0IGU31oaXRnaXFtZnZnc3drZDc4NjQu...  
  
  
 LLM 侦探破案过程：  
  
  
 🔍第一步：发现加密内容，解码发现命令组合  
  
  
 nslookup cname ***********.bxss.me  
  
  
 curl ***********.bxss.me  
  
  
 💡关键洞察：域名解析指向恶意IP，curl指令发送请求  
  
  
 🚨 结论：这是一起恶意攻击！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdelv3p055olaj2gEf5YwaQS8ibyWyibJ8E1hHG4iaX80pmWdEd4j1gO1ATtxwI1wzveVXiaaeOrVgtKzqg/640?wx_fmt=png&from=appmsg "")  
  
  
大模型优化与多模型协作  
  
提升网络攻击检测的  
  
效率与准确性  
  
  
  
那如何将大模型应用到EdgeOne中呢？接下来将介绍我们在落地实践中遇到的问题和解决思路。  
  
  
思维链CoT训练法：借鉴CoT的prompt调优提升攻击识别能力   
  
  
由于http流量攻击内容可能出现在流量中各个字段内，并进行编码加密等操作隐藏攻击，简单的prompt指令，模型可能分析不足导致漏检。  
  
  
在prompt调优过程中，借鉴CoT思维链思路，根据现网攻击流量特征，给出判定一个请求是否是Web攻击的分析过程，引导大模型按照步骤逐步分析，最终确认结果，就像福尔摩斯通过案件细节一步步推理得到最终真相！  
  
  
场景CASE：攻击者试图探测源站是否存在源码压缩包的攻击行为识别  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdelv3p055olaj2gEf5YwaQS8gTkvfOD872sJjKXLmpP19PEp4zNLbV95xznDbblSluGlcpzKicomCkw/640?wx_fmt=png&from=appmsg "")  
  
  
大模型瘦身计划：微调小参数模型提升检测效率  
  
  
随着EdgeOne客户流量规模激增，大参数模型因计算复杂度高、推理延迟大，难以满足高效检测需求。通过领域知识蒸馏，可将大模型能力迁移至小参数模型。  
  
  
小参数模型所需的资源成本更低，处理性能更快。但是通过对比评测，小参数模型在攻击样本的检出和白样本识别准确性均弱于大参数模型，通过蒸馏大参数模型的攻击判定数据，微调小参数模型，在样本集评测上达到接近大参数模型效果。  
  
- 数据：7000条（包括多种攻击类型样本和白样本）  
  
- 基座模型：hunyuan-3b\qwen2.5-3b\llama3.2-3b  
  
- 微调方式：lora  
  
蒸馏大模型的微调数据样例：（带有分析过程内容）  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdelv3p055olaj2gEf5YwaQS82IrxYwKwecOib8jZJibKphgPBcOmtCGg8XSee8RZR1FFzUzRY5k4Njjg/640?wx_fmt=png&from=appmsg "")  
  
  
LLM侦探联盟：多模型联合投票  
  
  
这里同时进行了多个基座小模型的微调，包括hunyuan-3b，qwen2.5-3b，llama3.2-3b小参数模型，在测试样本集攻击检出率和白样本识别率方面，各有优劣，通过分析差异样本，腾讯混元模型在5个攻击类型场景中的3个表现较优，2个可以和其他模型互补，进一步设计3个小模型联合投票检测方案，以提升整体检测准确率。  
  
  
检测逻辑：超过2个模型判为攻击即攻击，超过2个模型判为正常即正常。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdelv3p055olaj2gEf5YwaQS8aWp5uCmHvZZKBjKey21hfhySkd2OibKQbJ2cQpQBicC2Da1uyxnaPR6A/640?wx_fmt=png&from=appmsg "")  
  
  
➢在样本集的评测效果如下：  
  
  
经过多模型取长补短，整体攻击检测攻击准确率较单一模型有所提升，同时也达到接近大参数模型效果。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdelv3p055olaj2gEf5YwaQS8rJHibDXicdhwXgNZ1CWRodHQf8o4hMK9Xibp0vA5iaubUXYtZBRBHiak4RA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdelv3p055olaj2gEf5YwaQS8oyOxx4K641eiaNLNq8vhN36qun6cdPJITNibwic7YQS5icU4UVBrnmU0Zw/640?wx_fmt=png&from=appmsg "")  
  
  
➢第三方工具blazehttp评测如下：  
  
  
blazehttp（https://github.com/chaitin/blazehttp）为业界较知名的公开的第三方测评Web流量攻击检测效果工具，总样本33000+条，涵盖各类攻击和正常样本。EdgeOne的漏洞防护严格模式准确率超99%，误报率仅为0.4%。  
  
  
网络安全的未来展望  
  
从防御到智御  
  
  
  
数字孪生沙盒  
  
  
 在真实环境之外构建数字镜像，AI在这里可以：  
  
  
 ✅放心测试新规则  
  
  
 ✅模拟攻击演练  
  
  
 ✅验证模型可靠性  
  
  
 在EdgeOne漏洞防护处于观察模式阶段的域名命中规则的请求进行离线大模型判定，并提前自动剔除不适合业务的策略，达到自适应的效果，就像拥有一支永远不知疲倦的安全特种部队！  
  
  
0day猎杀计划  
  
  
 结合RAG技术，实时关联威胁情报与漏洞库，流量特征识别0day攻击。  
  
  
 流量特征 → 语义解析 → 威胁知识图谱 → 全球攻击样本库 → 自动生成防护策略  
  
  
 当大模型遇上网络安全，我们不仅造出了更聪明的检测工具，更重新定义了防御的边界。这场持续升级的攻防战，正在见证 AI 如何从旁观者变成守护者的蜕变历程。在你安全浏览网页的背后，或许正有看不见的 AI 侦探在为你守护安全！🛡️  
  
  
 EdgeOne标准版抢先体验，专属活动低至 4.5 折（1710 元/月起）（点击文末「阅读原文」查看更多活动信息），您可以通过托管规则-深度分析功能，率先体验EdgeOne对漏洞的识别能力。而基于大模型的漏洞识别能力，正在紧锣密鼓地规划与开发中，其将为漏洞检测领域带来革新性变化，敬请各位期待！  
  
  
 更多托管规则-深度分析信息请参考产品文档：https://cloud.tencent.com/document/product/1552/97403?from=eoweb  
  
  
 扫码可直接查看完整报告！后续我们将针对开发者和中小型企业推出两期更详细的安全报告解读，避免错失良机，建议扫码加入社群，获取最新动态👇  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdelv3p055olaj2gEf5YwaQS8ibM2UXWIdFvszmvcjrVaxhuUJbFpfPCtzHvwgmf4jJ27UCuHokmKs3A/640?wx_fmt=png&from=appmsg "")  
  
  
如果您想要进一步了解或使用 EdgeOne 相关能力，欢迎扫描下方二维码添加 EdgeOne 小助手，我们将安排产研同学专门跟进您的需求。或点击「阅读原文」进入EdgeOne官网了解更多。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qgibMaOglThJuXbW5YeK4TDIqPgXvsicpNB4F4KRHl2wDiaBib8FoiaoYZOUc6J7AuOfXLnIMicx8hyiajelNviaX2UViaA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
- END -  
  
  
**构建数字安全免疫力，守护企业生命线**  
  
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg5OTE4NTczMQ==&mid=2247526481&idx=1&sn=4c3df6a097139dcd269f02605c5288bf&scene=21#wechat_redirect)  
  
**二进制与LLM的碰撞：反混淆技术的新尝试**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg5OTE4NTczMQ==&mid=2247526517&idx=1&sn=1d00946ea3bf689b279f9318670cb530&scene=21#wechat_redirect)  
  
**2024漏洞风险启示录：在攻防的螺旋中寻找「治愈」之道**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg5OTE4NTczMQ==&mid=2247526425&idx=1&sn=720bc0dc67c58939f2189e19ffb5d9b4&scene=21#wechat_redirect)  
  
**DeepSeek爆火之下暗潮汹涌**  
  
  
  
  
