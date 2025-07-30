#  DeepSeek代码审计技术解析：从模型革新到漏洞挖掘实战   
原创 悟剑堂-千里  东方隐侠安全团队   2025-02-16 16:11  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4CIxxSk6mv96yVDPtG6a3wt01J7cOn7OpibUgZMdWm6fvQzO5FlrMnaxeDCnVicE1WibMA7wMNjsJOA/640?wx_fmt=jpeg "")  
  
#   
# 隐侠们的日常：关心武林  
  
  
蛇  
年新春前后，隐侠关注到DeepSeek名声大噪，  
低成本AI模型的崛起  
时代正式到来。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4RlQn8eeTqHMg2WY3ec78DwK53aeBvs6sVbtrZ5HQHC0G5SyYHGx8cnbMUibmbFUSZCAvn0aHYlRA/640?wx_fmt=jpeg&from=appmsg "")  
  
2025年初，中国AI企业深度求索（DeepSeek）凭借开源模型**DeepSeek-V3**  
和**DeepSeek-R1**  
引发全球关注。其模型以仅**OpenAI 7%的成本**  
实现同等性能，迅速登顶中美应用商店下载榜，甚至超越ChatGPT。这一突破得益于两项核心技术：  
- **Multi-Head Latent Attention（MLA）架构**  
：通过优化注意力机制，减少显存占用，提升算力利用率；  
  
- **动态流水线与MoE（混合专家）技术**  
：实现GPU指令执行“气泡”减少50%，支持338种编程语言的复杂代码处理。  
  
    DeepSeek的开源策略进一步降低了AI应用门槛，使其成为开发者与企业的首选工具。尤其在代码领域，其模型通过**多token预测**  
和**强化学习驱动的推理链（CoT）**  
，显著提升了代码逻辑分析与漏洞预测能力。      
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4RlQn8eeTqHMg2WY3ec78DpbVBPThacUk80WahXgcuP1X2BuZc1Gibusm21NtPbrv8bicPhsa6aUfw/640?wx_fmt=png&from=appmsg "")  
      
代码审计是对源代码进行系统性检查和分析的过程，旨在发现潜在的安全漏洞、编码错误、质量问题以及不符合最佳实践的地方 。  
  
   
   代码审计工作需要一定的知识储备。  
  
    首先，代码审计是为了发现代码里的安全漏洞，需要精通诸如 SQL 注入、跨站脚本攻击（XSS）、文件包含漏洞等常见安全风险的原理和代码表现形式。  
  
    另外，针对提升代码质量方面，需要检测代码中的逻辑错误、冗余代码、未使用的变量和函数等，提升代码的可读性、可维护性和可扩展性，则需要针对软件工程、代码可信、算法等进行深入掌握，以便能发现并去除冗余代码，能使程序结构更清晰，降低维护成本。  
  
    另外还需一定程度上了解规范和标准，确保代码遵循既定的编码规范、行业标准及企业内部规定，增强代码的一致性和规范性。  
  
  
      
在代码审计的实施上，主要分为  
人工审计和工具辅助审计  
两类。  
  
    人工审计方面，审计人员逐行阅读和分析代码，凭借自身经验和专业知识发现问题。此方法虽耗时费力，但能发现复杂逻辑问题和潜在安全风险。例如，通过仔细审查业务逻辑代码，可发现权限控制不当等问题。  
  
  
    工具辅助审计方面，运用专门的代码审计工具，如 Checkmarx、Fortify 等，对代码进行扫描。这些工具依据预设规则快速检测常见安全漏洞和代码质量问题，并生成报告。不过，工具可能产生误报，需人工进一步确认。例如，工具可能将一些正常的字符串拼接误报为 SQL 注入风险。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4RlQn8eeTqHMg2WY3ec78DWOyfCXGpPMCic98obuLvknYxG0KB1gH0pDjpEArEotR3GjJZmdvp0fA/640?wx_fmt=jpeg&from=appmsg "")  
  
      
在该技术背景下，  
代码审计面临如下核心挑战：  
  
1.海量代码与人力瓶颈：数据规模方面，现代企业代码库通常包含数百万行代码，人工审计效率极低（约200行/小时）；成本压力方面，资深安全专家年薪数十万，中小团队难以负担。  
  
   2.漏洞模式复杂化：新型攻击手法多样，如Log4j2/JNDI注入、Spring4Shell等漏洞，传统规则库难以覆盖；框架依赖复杂，Spring、ThinkPHP等框架的定制化漏洞需要深度上下文理解。  
  
    3. 误报与漏报问题：误报率高，静态分析工具（如Fortify）误报率普遍超过35%，增加人工验证负担；漏报风险，逻辑缺陷（如竞态条件）难以通过规则匹配发现。  
  
  
Deepseek的发展，或者前阶段Chatgpt、文心一言等的发展，已经让  
AI赋能代码审计成为了现实。  
  
如Deepseek已经可以在如下代码审计工作进行发力：  
  
     首先，多维度代码扫描方面，一是可实现敏感函数追踪：基于危险函数（如eval、exec）逆向分析参数传递路径；二是上下文感知分析：结合AST（抽象语法树）与数据流分析，精确判断用户输入是否可控。  
  
    在漏洞验证与修复建议方面，一是通过动态沙箱测试，自动生成POC验证漏洞可利用性，例如：  
  
```
# 自动生成的SQL注入测试Payloadpayload = "1' UNION SELECT username,password FROM users--"
```  
  
  
并可智能修复推荐，提供代码级修复方案（如参数化查询替换字符串拼接）。  
  
    在多语言与框架适配方面，AI无压力支持Java/Spring、PHP/ThinkPHP等主流框架的审计规则库；并可通过动态学习率调度器优化不同编程语言的模式识别效率。  
  
  
    接下来，以Mirror-Flowers等开源项目为例，展现DeepSeek应用下的多场景优势。  
  
    但是有些小遗憾的是，因为最近太忙，只能每个工具正向尝试一波，因为环境和操作等原因，可能工具使用效果没有达到预期，师傅们还是要自己搭建试试，如果有进展可以在评论区一起互动起来。  
  
      
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4CIxxSk6mv96yVDPtG6a3wMsQu6M3GSichtOicTFFy5t2AkcYiaxtaGc0HBEUxhgfFObGaoStDHGc8Q/640?wx_fmt=jpeg "")  
  
# Mirror-Flowers、Continue、AICodeScan  
  
Mirror-Flowers  
  
Mirror Flowers 是一个基于 AI 的代码安全审计工具，能够自动检测代码中的安全漏洞。项目地址：https://github.com/Ky0toFu/Mirror-Flowers  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4RlQn8eeTqHMg2WY3ec78D1BjLUj5c30YZQaBNBCMXTp9icic11O4SVj737YIAkWmudNs18BAq5ziag/640?wx_fmt=png&from=appmsg "")  
  
    特性如下：  
- 支持多种编程语言（PHP、Python、Java、JavaScript）  
  
- 本地静态代码分析  
  
- AI 驱动的漏洞验证和分析  
  
- 详细的安全报告和修复建议  
  
- 支持单文件和项目文件夹分析  
  
- 深色/浅色主题切换  
  
- 实时分析进度显示  
  
    支持的API接口如下  
：  
  
```
FREEGPTAPI：https://github.com/popjane/free_chatgpt_apiSiliconFlow(硅基流动)：https://cloud.siliconflow.cn/i/JzMCyiJ3
```  
  
  
     
 如需要使用GPT大模型则使用FREEGPTAPI，使用DeepSeek-R1大模型则使用SiliconFlow API。如：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4RlQn8eeTqHMg2WY3ec78DSRNdSpqIuGyWK8FWVN4l4tYVZ3iat3lGd8UHf6erWdibBSPrAwZKymnA/640?wx_fmt=png&from=appmsg "")  
  
     
 安装过程查看Github，找到相应安装指导命令，执行即可，在此不再赘述。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4RlQn8eeTqHMg2WY3ec78DkUPiaMBp8RZMA3PsCaNZlogpliaWHicpERWbMpeDvSWqVVWaDd8ClOW7Q/640?wx_fmt=png&from=appmsg "")  
  
  
     
 下面我们进行实际使用尝试，这里用phpcms v9源码进行审计测试：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4RlQn8eeTqHMg2WY3ec78D2ibuWCQly6bX459WfoKTp7WusqGbh0Rq1kr80kBfzkVwDFG3ZBtB91w/640?wx_fmt=png&from=appmsg "")  
  
      
命令行中可以看到进行相应调用：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4RlQn8eeTqHMg2WY3ec78D13PK6IRHrGNjR35v0deBwqGL1OAMHPWibJmN4MambVRHDjZlOJyruwg/640?wx_fmt=png&from=appmsg "")  
  
      
审计速度非常快，仅花费三分钟，完成静态分析，但发现该项目的展示效果一般， PHPCMS V9.1.13存在任意文件包含漏洞，但这里也并未发现相关文件路径结果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4RlQn8eeTqHMg2WY3ec78DcDYcxrhBDg1Hjc6LUJ7Aooyg1fg3zHYic4TibJz7kEpPRicLQnpmxmm8w/640?wx_fmt=png&from=appmsg "")  
  
      
  
Continue  
  
    接下来使用Continue，这个插件专为开发设计的开源工具，可以连接任何模型和任何上下文，可在VS Code和JetBrains IDE中构建自定义的自动补全和聊天体验，通过自然语言与代码互动，可以帮我们自动生成代码、解决编程中的疑问、识别代码漏洞、漏洞解释及提供修复建议等多种功能。  
  
    我在VSCode上面进行演示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4RlQn8eeTqHMg2WY3ec78Dr1qvkvPjR3uKALUCVWsZZI45iciaRAjMYfVr1ial1icrGkfR8dHp8ImBMA/640?wx_fmt=png&from=appmsg "")  
  
      
Continue给出了示例代码，可以看到如果购买了API套餐，则可以进行代码审计和优化询问（最近api充值貌似停止了，此处见谅哈）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4RlQn8eeTqHMg2WY3ec78D7zgsQ6qqpz73A4ichZM8GxvqpIZw0usCQnb6n6nS8sVH9EcFvEAtsaQ/640?wx_fmt=png&from=appmsg "")  
  
  
AICodeScan  
  
    该工具基于Zjackky师傅的CodeScan开发，通过对大多数不完整的代码以及依赖快速进行Sink点匹配，并且由AI进行审计精准定位，来帮助红队完成快速代码审计，目前工具支持的语言有PHP，Java，并且全平台通用。根据目前的存量规则，我们主要看它的实现思路。  
  
    项目地址：https://github.com/Zacarx/AICodeScan  
  
    在程序当前目录增加config.yaml，config.yaml内容为：  
  
```
api:url: "https://api.siliconflow.cn/v1/chat/completions"keys:    - "sk-bgrrpkmbbrksvrobipjynezdpnsfuezsmcgwebsslzycwdfh"    # https://cloud.siliconflow.cn/i/PE5EFD4U    # API池,可以增加多个api，闲鱼买到很多api.    settings:  # 每次调用ai间隔时间，防止频繁或者封号sleep_seconds: 3model:  # 模型名称name: "Qwen/QwQ-32B-Preview"# 这里%s不要动，防止输入错误prompt:text: "请分析以下代码是否存在安全问题：\n文件: %s\n行号: %d\n内容:\n%s\n当前行：%s，请简明扼要，如果觉得大概率没有漏洞直接回答\"大概率没有漏洞\"七个汉字。如果有，严格按照一下格式输出：\n漏洞类型：\n危害等级：\n判断理由：\n payload：，注意这里的冒号为中文冒号,每行前无空格"
```  
  
  
   实现效果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4RlQn8eeTqHMg2WY3ec78Dh9N0az6Mzbu9Yg1aTdhkDUnJ1dRYrBIK139O4BAlbicCb8CVzTYowNQ/640?wx_fmt=png&from=appmsg "")  
  
      
命令行用法：  
  
```
Usage of ./AICodeScan:  -L string        审计语言  -d string        要扫描的目录  -h string        使用帮助  -lbstring        行黑名单  -mstring        过滤的字符串  -pb string        路径黑名单  -r string        RCE规则  -ustring        文件上传规则
```  
```
Example:  AICodeScan -L java -d ./net  AICodeScan -L php -d ./net  AICodeScan -d ./net -m"CheckSession.jsp"
```  
  
  
      
现在继续使用phpcms的代码进行测试：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4laNHWaR5yOd2VbInJbO4hh98l9JVcSWKvpestXbdjjAUwScNRbaaS7fST9BLEViaGibSlooicibt86Q/640?wx_fmt=png&from=appmsg "")  
  
    查看结果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4laNHWaR5yOd2VbInJbO4hWF9Pknib9RmZBEVT3Qe0KMbnBvsDce8FI4JrbFNv3TRLn82UsIZzaKQ/640?wx_fmt=png&from=appmsg "")  
  
      
通过AI对所有疑似漏洞进行了分析：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4laNHWaR5yOd2VbInJbO4hZAEmF4eFZvN10B4ezicJ5mJfSPEcic4OWMNeibNtwxjeKEwX9KReiaqPlQ/640?wx_fmt=png&from=appmsg "")  
  
      
有趣。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4CIxxSk6mv96yVDPtG6a3w6JRYCkhyIhdhMreJKaG9RoxIKN935mPFa7LFK0Ka6pN5gvWiaKz7a4A/640?wx_fmt=jpeg "")  
  
  
AI 代码审计的未来展望与挑战  
  
  
    从当前的发展态势来看，AI 代码审计未来充满机遇，同时也面临诸多挑战。在技术发展方向上，随着模型架构的不断优化，如 DeepSeek 的 MLA 架构和动态流水线与 MoE 技术，有望进一步提升审计效率和准确性。未来的 AI 代码审计模型可能会更加智能，不仅能检测常见漏洞，还能对新型、复杂的漏洞模式进行深度分析，降低误报和漏报率。  
  
    在应用场景拓展方面，AI 代码审计不会局限于现有的开源项目或特定编程语言。它将更多地融入  
企业级开发流程，从代码编写、测试到部署的全生命周期进行安全监控。例如，在持续集成 / 持续交付（CI/CD）管道中集成 AI 代码审计工具，实现实时检测代码变更中的安全风险，确保软件产品在上线前的安全性。  
  
  
    AI 代码审计正处于快速发展的阶段，虽然目前存在一些问题，但未来潜力巨大。  
数据隐私和安全问题是重中之重，代码审计涉及大量企业敏感代码，AI 模型在处理这些数据时，如何确保数据不泄露、不被恶意利用，是亟待解决的问题。同时，AI 模型的可解释性也是一个关键挑战。当模型给出漏洞检测结果时，开发人员和安全专家需要理解模型的判断依据，以便进行有效的修复和决策。但目前许多先进的 AI 模型结构复杂，难以直观解释其决策过程。  
  
    只有在技术创新、安全保障、标准规范等多方面协同发展，才能让 AI 代码审计更好地服务于软件开发和安全保障领域，为数字世界的安全保驾护航。  
  
    为了更直观地了解 AI 代码审计的发展趋势与相关技术，推荐参考以下网络资源：  
- Gartner 对 AI 安全技术的分析报告：该报告对 AI 在安全领域的应用，包括代码审计方面，有深入的分析与预测。  
  
(  
https://www.gartner.com/en/doc/impact-of-generative-ai-technical-landscape-enterprise-applications)  
  
- OWASP 关于 AI 辅助网络安全的知识库：  
  
(https://owasp.org/www-project-top-10-for-large-language-model-applications/)  
  
  
关注东方隐侠安全团队 一起打造网安江湖  
  
        
  东方隐侠安全团队，一支专业的网络安全团队，将持续为您分享红蓝对抗、病毒研究、安全运营、应急响应等网络安全知识，提供一流网络安全服务，敬请关注！  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH7zgibKsqKmX3H4AatvwPeXFsrHGpp0RsxLJpzgd0cyiaPH2HDnfv4GMdxf0lkGjAibiaBtFcLmnm2ZkA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
公众号｜东方隐侠安全团队  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4laNHWaR5yOd2VbInJbO4h3daHtdT7pcSk7zONRMDyl2cht3U4dbbyiaLmMA5DpBBlTgspa3agKyw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
请添团队微信号｜东方隐侠安全团队  
  
用于拉少侠们进团队微信群  
  
  
