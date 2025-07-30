#  【大模型与安全】第三弹：LLM与 Fuzzing 技术在漏洞挖掘中的应用   
 默安玄甲实验室   2025-04-10 11:50  
  
随着大语言模型（下统称LLM）的兴起，其在软件安全测试领域的应用前景备受瞩目。传统模糊测试（下统称Fuzzing）依赖人工编写测试用例和规则，这种方法不仅耗时费力，还难以覆盖复杂的输入空间。而LLM凭借其强大的生成能力，擅长解决传统上需要大量人工才能完成的重复任务，这为Fuzzing引入了新的变量。  
  
  
在Web应用领域，漏洞挖掘面临着不断强化的WAF和日益臃肿的字典。传统的Fuzzing技术虽然行之有效，但在处理复杂的Web应用程序时存在效率低下、覆盖率不足和误报率高等问题。LLM凭借其强大的自然语言理解和生成能力，为Web安全Fuzzing提供了新的技术路径和方法论 。基于信息保护原则，以下LLM测试用例均在本地运行。  
  
## 01 从枚举到预判：探索Web渗透新姿势  
  
  
过往的一些研究认为(https://arxiv.org/pdf/2409.10737)，LLM在代码精确分析方面存在局限性。静态应用安全测试(SAST)作为软件安全生命周期的重要环节，能够在早期阶段系统性地识别代码中的潜在漏洞和安全缺陷，为开发团队提供宝贵的安全指导。然而，SAST工具也面临假阳性率高和上下文理解有限等挑战。在这种情况下，LLM辅助的模糊测试可以作为SAST之后的有效补充，形成更完整的安全测试体系。  
  
  
与静态分析的确定性不同，模糊测试本质上是一个主打随机探索的过程，测试用例的生成需要具备高覆盖率和多样性，同时能够探索程序的边界条件和异常路径。从这个角度来看，接入了定制化RAG的LLM能够更精准地理解测试目标和需求，从而提供更贴合实际场景的测试策略和漏洞分析。特别是在接入MCP之后，LLM能够直接与专业逆向工程工具配合，实现符号表重建和源代码重构等高级功能，进一步增强了动态测试的能力与价值。  
  
  
传统的Web安全Fuzzing技术主要包括以下几种：  
  
  
01  
  
  
**基于随机生成（Random-based Fuzzing）**  
  
• 实现原理：随机生成输入数据，缺乏语义理解  
  
• 技术局限：低效率、高误报率、难以发现深层次逻辑漏洞  
  
• 代表工具：Radamsa、zzuf  
  
02  
  
  
**基于变异（Mutation-based Fuzzing）**  
  
• 实现原理：基于已有输入样本进行变异  
  
• 技术局限：依赖初始种子质量，难以生成结构复杂的攻击向量  
  
• 代表工具：AFL、honggfuzz  
  
03  
  
  
**基于语法（Grammar-based Fuzzing）**  
  
• 实现原理：根据预定义语法规则生成符合特定格式的输入  
  
• 技术局限：规则构建复杂，难以适应多样化的Web应用  
  
• 代表工具：Peach Fuzzer、Domato  
  
  
我们将传统Web安全中的Fuzzing定义为以特定字典为基础，通过生成和发送大量随机化或变异化的输入数据评估Web系统安全性的方法。随着Web应用程序的复杂性不断增加，传统Fuzzing方法在面对大型、动态的Web系统时逐渐显露出效率低下、覆盖不足的问题。  
  
### 02 开局一个框，路径全靠猜  
  
  
在渗透测试中，有一个非常典型的场景：面对一个登录框，如何有效突破目标系统。通常，渗透手会首先尝试弱口令登录、设置JavaScript断点以及进行密码爆破等常规方法。然而，当这些路径均无法取得突破时，我们往往会将注意力转向目标系统的供应链，或者深入探索其Web路径和接口。  
  
  
目前思路的核心是将人工智能的语义理解能力与传统模糊测试技术深度融合。因此设计了一个多阶段的Fuzzing流程，主要包括五个关键环节：初始信息收集、AI语义分析、路径生成、模糊测试和持续学习。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/50Hiagic8dst5G2BRx8I7Tu7XQmYolbZpDOkRd2iameUmhthljDSm6AbNYFXherjRcfcpTdWvXBtiaSz3FDuywsCiaA/640?wx_fmt=png&from=appmsg "null")  
  
  
局域网环境搭建了一个Demo，电商后台站点，闭源产品，正常访问只返回了index.jsp与login.jsp、404.jsp，本地搭建LLM并给其投喂了一定量该类站点渗透测试报告，进行实验对比。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/50Hiagic8dst5G2BRx8I7Tu7XQmYolbZpDia7jfgV1eeJSCMNvOjm6jXiapH0BpWjmYcHAelUj9jzU1GaWfjavwYqw/640?wx_fmt=png&from=appmsg "null")  
  
  
我们采用实验组和对照组的设置，以科学地评估不同测试方法的效率和效果。实验组采用基于LLM的Fuzzing方法，而对照组则使用传统的基于字典的模糊测试方法，采用dic.txt字典进行爆破。经过若干组对比测试:  
  
  
实验组（LLM Fuzzing）：  
  
发送请求数：328次  
  
发现的有效子路由：10个  
  
有效请求/发送请求数比例：10/439 ≈ 3.04%  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/50Hiagic8dst5G2BRx8I7Tu7XQmYolbZpDm9YoUia6jD7gdaP2z31bySDwW9srALKnVGXtN75vw8eCV9vLiaUCg8yg/640?wx_fmt=png&from=appmsg "null")  
  
  
对照组（基于传统字典Fuzzing）：  
  
发送请求数：43252次  
  
发现的有效子路由：3个  
  
有效请求/发送请求数比例：3/43252 ≈ 0.006%  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/50Hiagic8dst5G2BRx8I7Tu7XQmYolbZpDO2ibTs7fg6bLZYKsKDLBjWiao38rbQs9Rbh6SEjOVria3zEEicX5S3OiayQ/640?wx_fmt=png&from=appmsg "null")  
  
### 03 探索自适应注册表单  
  
  
以某支付系统API为例，该平台是一个支持多币种交易的支付平台，为在线商户提供全球支付解决方案。该平台支持超过50种货币，并提供实时汇率转换。系统架构包括支付处理、退款处理、结算和报表等多个微服务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/50Hiagic8dst5G2BRx8I7Tu7XQmYolbZpDcNrYRttgdagWNqfAPtP0KmZy0Tqv1Btj49dlf8xaibibXIT9zhk6UYSA/640?wx_fmt=png&from=appmsg "null")  
  
  
官方API给出JSON如下,传统的Fuzzing思路应该包括:  
  
  
• 随机改变金额字段：如"amount": "43.43"  
 → "amount": "999999999"  
或"amount": "-10"  
  
• 随机插入特殊字符：如"amount": "43.43!@#"  
  
• 传入极端值：如非常大或非常小的数值，"amount": "0.0000001"  
或"amount": "9999999999999"  
  
• 在参数中插入SQL语句：如"order_id": "ORD123' OR 1=1--"  
  
• 提供空值：如"refund_amount": ""  
等。  
  
```
```  
  
  
在测试过程中，LLM编写的测试案例发现了一个有趣的现象：当USD兑换为VND时，由于汇率极高（约1:25600），转换后的金额可能超出系统精度限制。进一步测试显示，当退款处理时，系统会对VND金额进行四舍五入，然后再转回USD，导致退款金额可能大于原始支付金额。  
  
```
```  
  
  
在攻防演习中，确实经常遇到需要注册各种供应商平台或企业平台的情况，包括但不限于:  
  
  
• 供应商/合作伙伴注册平台  
  
• 企业招投标系统  
  
• 行业垂直门户网站  
  
• 政府采购平台  
  
  
而这些平台的注册流程往往非常繁琐且耗时，而且不一定注册了就有结果，往往成为漏网之鱼。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/50Hiagic8dst5G2BRx8I7Tu7XQmYolbZpD4lXTibVMmjjlTKvkhuibPS5r6DBQvY0J1kR21Vx8VnucYvfqIqXvCoPQ/640?wx_fmt=png&from=appmsg "null")  
  
  
以某单位供应商平台为例，估计看到这密密麻麻的注册项目心已经凉了一半了，但很多成果就在这马奇诺防线之后。这类供应链相关平台通常是企业数字化转型的重要环节，其中包含了大量敏感的业务数据和用户信息。供应链攻击已成为高级持续性威胁组织的首选手段之一，因为它们可以利用上游供应商的弱点来渗透目标组织的网络环境。特别是在多级供应链结构中，攻击者可能通过最薄弱的环节获取初始访问权限，然后横向移动至核心系统。尤其是部分供应商系统在用户注册到人工审核期间，账号便具备包括通过token SSO到其他周边平台的能力。针对该种情况设计以下Fuzzing方案:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/50Hiagic8dst5G2BRx8I7Tu7XQmYolbZpD646qpJDUeBnE8IazQowZ66WrgazPjmO2CsPv63BTJMiaLUgywr8ia02w/640?wx_fmt=png&from=appmsg "null")  
  
  
根据具体需求可针对验证码环节，可接入OCR技术，实现自动识别和输入，提高注册成功率；针对不同行业的供应链平台，构建专用的数据字典和业务逻辑模型，提高测试的精准性和覆盖率；利用供应商关系图谱分析，识别潜在的高价值目标和攻击路径，优化测试资源分配；根据不同平台的规则，自动化生成不同类型的测试账户，避免被单一规则拦截；同时，可设计智能爬虫系统持续监控供应链平台的更新和变化，及时发现新增功能或变更带来的安全隐患，对于甲方，也可以通过该系统进一步覆盖传统扫描器所覆盖不了的攻击面。  
###   
### 04 未来展望  
  
  
随着大语言模型（LLM）技术的持续进步，它在安全测试领域的应用潜力仍在不断挖掘。从当前的实践来看，LLM不仅提升了Fuzzing的自动化程度，还在漏洞挖掘的精准性和效率方面展现出巨大优势。然而，现阶段的LLM Fuzzing技术仍然面临一些挑战，例如：  
  
  
01  
  
**数据质量与泛化能力**  
  
LLM的表现高度依赖于训练数据的质量，低质量的数据可能会导致模型产生误导性结果。  
  
02  
  
  
**计算资源消耗**  
  
高效的Fuzzing需要大量计算资源，集成LLM后，对算力的需求更为苛刻。  
  
03  
  
  
**安全性与稳定性**  
  
LLM本身的安全性问题，如幻觉和潜在的攻击面，仍需进一步研究。  
  
  
尽管如此，LLM的自适应能力和推理能力使其成为Fuzzing技术发展的关键推动力。未来，我们或将看到更智能的漏洞挖掘框架出现，其中LLM不仅能够协助测试用例生成，还能基于实时反馈动态调整测试策略，从而提高攻击面的覆盖率。  
  
  
# 参考：  
  
1.  
https://www.superannotate.com/blog/llm-prompting-tricks](https://www.superannotate.com/blog/llm-prompting-tricks)  
  
2.  
https://s4plus.ustc.edu.cn/_upload/article/files/a7/b0/2eb02e99473299310e1afed636b2/a14645cb-788b-466b-94e4-d74d2e166bdd.pdf  
  
3.  
https://security.tencent.com/index.php/blog/msg/28  
  
4.  
https://www.invicti.com/blog/security-labs/brainstorm-tool-release-optimizing-web-fuzzing-with-local-llms/  
  
5.https://github.com/danielmiessler/SecLists  
  
  
  
  
  
