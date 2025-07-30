#  风云卫×DeepSeek-R1（四）：当AI侦探团遇上“漏洞迷案”   
 绿盟科技   2025-02-27 09:56  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/IpYUt4DIvZeL3Gg17RG9icEiaWz5ialGG2Hv0LzibHuyOTd1LzSUaVicukdQUdIVfHuuicqibj25bXX0AhIDWjNKnMicRg/640?wx_fmt=gif "")  
  
  
全文共**3126**字，阅读大约需**6**分钟。  
  
  
  
在绿盟科技，一场关于漏洞分析的“最强大脑”对决正悄然上演。绿盟科技的安全专家将DeepSeek-R1的深度推理能力应用于漏洞情报分析，探索其在这一领域的潜力与可行性。在与风云卫安全大模型进行实测对比后，我们发现，DeepSeek-R1在问题分解和知识整理上展现了卓越的能力，有效提升了绿盟漏洞分析智能体的整体性能。未来，绿盟科技将继续深入研究，探索两者的深度融合与能力拓展。  
  
  
一  
  
漏洞档案解密术：信息抽丝剥茧  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CkzQxaHZX9KdW919vwagVwhCeicQPXuMGibHcf2WqiaFyvfy5p1oIk1C5SOdtTyLlQmOtEia7FMKicknJzGTmYLWb2Q/640?wx_fmt=gif "")  
  
**任务一：根据漏洞描述文本提取相关实体**  
  
在安全知识图谱的构建过程中，通常采用自然语言处理（NLP）技术栈对多源异构文本进行深度解析。通过预训练语言模型（如BERT、RoBERTa）进一步微调构建出实体关系识别模型提取安全领域实体和关系，结合预定义的本体模式（OWL/RDF Schema）完成概念与实体映射、实体与实体连接，支撑安全知识图谱的自动化构建与推理。在漏洞信息实体抽取任务中，我们定义的实体类型包括受影响产品及版本、漏洞产生原因、漏洞造成影响、攻击者类型、攻击方式等。为此，我们分别将相同的漏洞描述文本和目标实体类型输入到DeepSeek-R1和风云卫两个大模型中，进行实体识别并格式化操作。以CVE-2009-1234（Opera 远程拒绝服务漏洞）为例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZTSIYOTOiayB4Sialh7wuIvP9CNuIZhg5Z4oSUdBtaZmG0CgInLDvtqzA/640?wx_fmt=png "")  
  
图 1 CVE-2009-1234漏洞描述  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZiaYOTfCiacxBnFGJhylwNDvDNBrQYxN5T36RpyFgYMvSFgbvAAeJfTFg/640?wx_fmt=png "")  
  
图 2 实体识别结果对比  
  
**实测结果表明：两个大模型都能比较轻松地理解漏洞描述文本，能遵从指令提取对应实体，并以JSON格式输出。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CkzQxaHZX9KdW919vwagVwhCeicQPXuMGibHcf2WqiaFyvfy5p1oIk1C5SOdtTyLlQmOtEia7FMKicknJzGTmYLWb2Q/640?wx_fmt=gif "")  
  
**任务二：分析漏洞描述文本预测漏洞类型**  
  
在漏洞类型（CWE）预测任务中，我们的目标是通过分析漏洞描述，提炼漏洞产生原因，并将其正确分类到相应的CWE类型中。此任务中，我们仅提供漏洞描述文本，让大模型基于其知识储备进行自动分析。以CVE-2021-0256漏洞描述为例，NVD官方将其分类为CWE-269（Improper Privilege Management）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZhXibDwRmp9KaDCywb8NbUYSNYeZMaKOD590CI9hBjoaKt4pUlkhQuXA/640?wx_fmt=png "")  
  
图 3 CVE-2021-0256漏洞描述  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZzE5gmDo7vPicOMgBwSKiaFWf1SYHsARE2OqkxACibJekPIeQ65oDUx2TQ/640?wx_fmt=png "")  
  
图 4 漏洞类型(CWE)预测结果  
  
**实测结果表明：DeepSeek-R1展现了出色的深度分析能力，能够细致地分析漏洞描述中的根本原因以及潜在影响，进而精准匹配相关CWE类型。相较之下，风云卫由于缺乏深度分析，仅从表面描述进行简要分析，最终给出的CWE类型虽然相关，但不够准确。**  
  
二  
  
专业问答：背景知识助力深度推理  
  
我们选择了两组漏洞，一组是热度一般的漏洞（如CVE-2015-2477），另一组是热度较高的漏洞（如CVE-2017-0143、CVE-2021-44228），分别采用有/无额外背景知识两种模式让大模型进行解答。  
  
  
在不提供额外背景知识的模式下，两个大模型都表现出对热度高的漏洞回答的效果要好于热度一般的漏洞。推测原因可能与训练数据有关，热度高的漏洞通常在互联网上会有更多讨论，因此能获得更多训练语料，有利于模型“记住”这类漏洞，而对于热度一般的漏洞则会存在或多或少的“幻觉”问题，但DeepSeek-R1的结果与实际的漏洞信息更相关，且答案组织形式更清晰。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZAv1a99GyFibbfOp2bJnHsnWrcPJZo4fnCvQ9Jf3cqokGREPiaKBdicm9w/640?wx_fmt=png "")  
  
图 5 热度低漏洞CVE-2015-2477 office内存损坏漏洞 - 均回答错误  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZ4xD0FncCo2dSCeY6t3gYLyqEdP8xVS6pFDd5VduTElOTlJIXYruPfA/640?wx_fmt=png "")  
  
图 6 热度高漏洞CVE-2021-44228 log4j漏洞 - 均回答正确  
  
在提供同等额外背景知识（绿盟漏洞知识图谱）的模式下，两个大模型生成答案的准确率明显提升，答案内容差异不是很大，漏洞的主要信息都能呈现出来。就细节而言，风云卫罗列的漏洞信息没有进行优化处理，如区分重要信息和次要信息；DeepSeek-R1除了从背景知识中提取漏洞基本信息外，还进一步分析了漏洞原理和潜在影响，在其深度思考过程中对CVSS（通用漏洞评分）向量进行解读提炼出了“用户交互”这个特征作为漏洞修复的一条建议，在答案的整理输出上更有条理、重点突出。以CVE-2015-2477 office内存损坏漏洞为例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZFrkVrHmKexIcm2V8ibCFDzjVANEOSb0nSmtIORhmAMIWz2sSWaudthg/640?wx_fmt=png "")  
  
图 7 DeepSeek-R1深度思考过程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZbfXjnFqMG7yiaf0cpQCHibaSk7xLqCuFnicKNMXCPeFSwNlBsUA0b8kZA/640?wx_fmt=png "")  
  
图 8 CVE-2015-2477 office内存损坏漏洞 - 均回答正确（左侧是风云卫的回答，右侧是DeepSeek-R1的回答）  
  
**从两组测试结果可以看出，在漏洞知识问答场景中，单靠大模型自身能力显然是无法完全正确回答专业性问题，多多少少会夹杂“自我生成”文本。在离开相关专业知识/背景数据的引导，大模型的表现就看谁掌握的“知识”更多。在专业知识的问答上，RAG技术还是能为大模型提供不小的助力。**  
  
  
三  
  
PoC编写能力：大模型的应用潜力  
  
在常见的攻防场景中，安全人员通常会对新/老漏洞编写PoC-漏洞验证插件来完成自动化漏洞扫描的工作。大模型的强大文本生成能力如果能用于PoC编写，无疑会给安全测试人员带来极大的效率提升。我们选择了10组漏洞信息数据及相应漏洞攻击流量，并提供PoC编写规范，让大模型根据这些信息编写一个可用于验证漏洞存在性的PoC。这一环节要求模型一是具有PoC编写能力，知道编写PoC所需的基本要素；二是具有流量分析能力，能从流量中提炼出请求和响应检测内容；三是指令遵循能力，PoC有多种编写方式，这里需要按照prompt中提供的格式进行编写。以CVE-2022-82713 Golang pprof信息泄漏的HTTP流量为例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZc3cgBA6wW3YN5UnGP8fJY6LxS755gnk0lptY4Sajwr8ekRTD2icb3lVdG977JicsU9dT5VnE7RQrZg/640?wx_fmt=png "")  
  
图 9 CVE-2022-82713 漏洞的HTTP部分流量  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZVsFd7PURp1rcTYVbb1KBA8SfGogYD5e0OE80EMGbv6vyujzf74lEAg/640?wx_fmt=png "")  
  
图 10 PoC编写能力对比  
  
从结果上看，DeepSeek-R1显然是具备一定的PoC编写能力和流量分析能力，但是最后编写的PoC不符合格式要求且生成了一些额外字段。此外，DeepSeek-R1的答案生成时间是风云卫的3倍，其中思考过程耗时占据了70%左右，而且思考过程的输出长度约是最终答案的4倍，有很大一部分是在做参考示例的理解和生成结论的判断。可是在有些测试例中这未能为生成正确答案提供明显增益。但不可忽视的是，DeepSeek-R1的深度思考功能中对漏洞和HTTP流量的分析过程，以及将提取的信息转换成PoC里对应字段的值的步骤，这些细粒度的分析可以给安全测试人员提供参考，让用户理解PoC编写的一些方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZM0Rib7JoqkmicGmRlABqdtpPUMZMpHLTvtJZ4FU2zibqrnuss9GiaXkS1g/640?wx_fmt=png "")  
  
图 11 DeepSeek-R1编写PoC的部分思考过程  
  
四  
  
智力跃升：漏洞情报分析的突破  
  
通过上述对DeepSeek-R1与风云卫安全大模型的对比与分析，可以看到DeepSeek-R1作为一项前沿的AI技术，其极具优势的自然语言理解能力、推理能力和答案组织能力在漏洞情报场景中展现出了应用潜力和价值。  
  
漏洞信息抽取：能够在理解实体类型和提取相关实体的基础上，运用推理能力分析其中的因果关系，识别出准确的实体。  
  
  
漏洞知识问答：能够拆解用户问题并逐个分析生成相关内容，同时进行结果一致性校验，将答案按重要度分层展示，以突出核心结论。  
  
  
漏洞PoC生成：能够分析漏洞信息和流量信息，根据PoC所需字段分解编写步骤，并按步骤提炼所需要素进行信息填充和有效性检查。  
  
相较而言，风云卫安全大模型虽然在问题的延申理解和答案组织上不如DeepSeek-R1出色，但其具备的领域知识、较快的推理速度和定制化能力仍然具有优势，能够更好地满足高响应需求场景和特定用户的独特需求。  
  
  
因此，如何在不过分牺牲性能的情况下提升风云卫安全大模型的深度推理能力是一项研究重点。正如之前文章[《风云卫×DeepSeek-R1（二）：让渗透测试决策秒变专家级》](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650465105&idx=1&sn=e18507269639649b88653949672d6c3c&scene=21#wechat_redirect)  
中所介绍的，风云卫安全大模型采用知识蒸馏技术将DeepSeek-R1作为教师模型将推理知识传递给风云卫安全大模型，使其习得了思考过程和推理步骤，训练出了具有深度思考能力的DeepSeek-R1-Distill-SecLLM模型。我们将该DeepSeek-R1-Distill-SecLLM模型作为漏洞情报分析智能体的后端大模型，在绿盟智能体平台上快速部署测试（如图12），接着就漏洞情报分析场景中的漏洞知识问答和漏洞PoC生成两项任务测试DeepSeek-R1-Distill-SecLLM模型的深度推理能力是否有效，如图13和图14所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZPqcic0NEFeynfRJOfZtVENJnIvHmEictqywkANTBiafEibvMKMo3j9SRjQ/640?wx_fmt=png "")  
  
图 12 漏洞情报分析智能体  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZVy4hqXkgTQJfpwQ8BCN9jN8TiaMiav0KVwUgSnadHknHhzpticl83XO4Q/640?wx_fmt=png "")  
  
图 13 DeepSeek-R1-Distill-SecLLM模型对CVE-2015-2477漏洞分析的思考过程和答案  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZfY62tc3e1O5DrNc5vJN9kZ2icBias1tWBk8KMlWbI6nShYia2mSCILQslSQhRKXot4NBgjqxWl0Dqcg/640?wx_fmt=png "")  
  
图 14 DeepSeek-R1-Distill-SecLLM模型对CVE-2022-82713漏洞PoC编写的思考过程和答案  
  
令人印象深刻的是，这个模型在以下几个方面表现突出：  
  
信息深度理解：模型能够以清晰的结构对信息内容进行梳理，使用户能够快速掌握重要信息。  
  
  
信息准确性判断：在思考过程中，模型会对信息的准确性和前后一致性进行评估，有效减少输出矛盾信息或错误信息的情况。  
  
  
透明的思考过程：模型在输出时提供详细的思考过程，这不仅增加了生成答案的可信度，还帮助用户了解模型的推理和决策过程。  
  
从耗时方面来看，增强深度思考能力并没有显著降低模型的推理速度。在简单任务上，其耗时与不具备深度思考能力的SecLLM模型相当；而在复杂任务上，耗时会增加约1倍左右，但仍然明显少于DeepSeek-R1。目前，这个DeepSeek-R1-Distill-SecLLM模型仍处于初期阶段，未来将继续优化其思考深度和答案生成的稳定性。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/xZBrQScF24AJKSgyOaF9TQSR5SKr3RZr8ticxvFEMOH1CvB0IDwDcRzCrhDX8wZcXzibA4XibYFwVcnH0iblicWKCWA/640?wx_fmt=gif "")  
  
DeepSeek-R1的深度推理能力对提升风云卫的问题分解延伸和知识整理能力产生了积极影响。尽管这一过程可能带来一些性能上的折衷，但在实际应用中，仍展现出巨大的潜力。我们将继续推动DeepSeek-R1等创新技术与风云卫安全大模型的深度融合，形成能力互补，共同打造更强大的安全智能模型与实用产品，为用户提供更加全面、高效的安全解决方案。  
  
   
  
本系列文章来自绿盟科技天枢实验室，旨在与安全界同仁共同探索DeepSeek创新技术的奥秘及其在安全行业的应用。绿盟科技将通过测试分析、原理阐释、应用方案和实践验证，希望能为读者揭开DeepSeek创新技术的神秘面纱，并分享绿盟科技在拥抱DeepSeek技术、解决实际安全问题中的实践经验与思考，以期抛砖引玉，共同推动智能安全的技术发展。  
  
**推荐阅读**  
  
- [深度整合丨绿盟科技集成DeepSeek，实现双模型底座共生](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650464881&idx=1&sn=646c35c19af3e54262b8e999d3462223&scene=21#wechat_redirect)  
  
  
- [全球AI技术博弈下的软件供应链安全 ——DeepSeek恶意软件包事件启示录](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650464795&idx=1&sn=01db962fae011f5776d30a62828d7cc2&scene=21#wechat_redirect)  
  
  
- [大模型内容安全：敢问路在何方？](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650448018&idx=1&sn=ebc73796562fe175f03dc6939ea62540&scene=21#wechat_redirect)  
  
  
- [警报：大模型正叩响“内容安全”大门](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650447496&idx=1&sn=e3e113b1ae15865bb2451e2147e69b25&scene=21#wechat_redirect)  
  
  
- [检测与防护：大模型信息泄露的安全「紧箍」](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650447103&idx=1&sn=d44c1f107a70aebcbb542bbb2af434e6&scene=21#wechat_redirect)  
  
  
- [大模型正在“记住”与“说出”](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650446627&idx=1&sn=154b38eb989dfe7b6872a823f23165d8&scene=21#wechat_redirect)  
  
  
- [报告深读 | 大模型安全风险与防护策略](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650444265&idx=1&sn=4a791774023761dc9c5db0b6d00a6edc&scene=21#wechat_redirect)  
  
  
- [风云卫×DeepSeek-R1（一）：能否突破安全运营中的告警难题？](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650465079&idx=1&sn=db0fb6ea59c46095f791ff9d54b03788&scene=21#wechat_redirect)  
  
  
- [风云卫×DeepSeek-R1（二）：让渗透测试决策秒变专家级](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650465105&idx=1&sn=e18507269639649b88653949672d6c3c&scene=21#wechat_redirect)  
  
  
- [风云卫×DeepSeek-R1（三）：如何跨越全球推广合规“雷区”？](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650465415&idx=1&sn=230c5bdc7a0abf1d8dacc14400b02f42&scene=21#wechat_redirect)  
  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/IpYUt4DIvZegkEFpP4fL9ibUPiaIFan451wLNJibXpcCOgfDV1cmlIjiczs3XZYibj8OFtZ7Tvf77mnTLp6LIERMm3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650464881&idx=1&sn=646c35c19af3e54262b8e999d3462223&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650464740&idx=1&sn=836012e50fca0894e9ce185d6dac6d26&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5ODYyMTM4MA==&mid=2650464739&idx=1&sn=605819e5c99ed944334560fe1df63dc6&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/IpYUt4DIvZegkEFpP4fL9ibUPiaIFan451jMWXWIA8yj3dEtLY9KIVzKGNbzZ9zzyVskGsFyAibiblgNSfOIPHN13w/640?wx_fmt=gif "")  
  
  
