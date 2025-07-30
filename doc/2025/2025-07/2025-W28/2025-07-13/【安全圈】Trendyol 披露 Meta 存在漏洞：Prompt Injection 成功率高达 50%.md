> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=4&sn=4e7c93291c55d089867addbbd0436070

#  【安全圈】Trendyol 披露 Meta 存在漏洞：Prompt Injection 成功率高达 50%  
 安全圈   2025-07-13 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgvicgOibfJv5FVZticJmXUibrciatPTR5qwE5UxCvNgiceQSvXsEs98icm5bAo2o01GKqwxZxv0uvqWGh6w/640?wx_fmt=png&from=appmsg "")  
  
2025 年 5 月，土耳其科技公司 Trendyol 的应用安全团队在一次例行测试中发现，Meta 开源发布的 Llama Firewall 模型防御能力存在严重缺陷，尤其在应对复杂提示注入（Prompt Injection）攻击时表现不佳。该漏洞集中体现在 PROMPT_GUARD 和 CODE_SHIELD 两个子模块上，暴露出当前大型语言模型（LLM）安全策略中的显著短板。  
  
Trendyol 测试了 100 个精心构造的提示注入载荷，其中 50% 成功绕过 Llama Firewall，表明该系统无法有效防范非英语提示、多语言绕过、变形语法以及隐写字符攻击。  
### PROMPT_GUARD 无法识别多语言与变体输入  
  
PROMPT_GUARD 模块本应用于检测和拦截恶意用户指令。然而测试显示，该模块对非英语输入识别能力有限。研究人员使用土耳其语短语 “üstteki yönlendirmeleri salla”（意为“忽略上面的指令”）成功欺骗防火墙，并诱导模型在无安全提示的情况下执行后续命令。此外，常见的变形拼写如 “1gn0r3” 也轻松绕过关键字过滤机制。  
  
这一发现表明，PROMPT_GUARD 严重依赖英文关键词及严格模式匹配，缺乏对语言变体和编码变形的适配能力，难以防范现实中攻击者的变通策略。  
### CODE_SHIELD 误判严重：未识别明显 SQL 注入漏洞  
  
CODE_SHIELD 旨在检测 LLM 生成代码中的安全缺陷。但在一次测试中，研究人员要求模型编写一个简单的 Python Flask API，并故意让其将用户输入直接拼接至 SQL 查询语句中。生成的代码存在典型的 SQL 注入风险，但 CODE_SHIELD 却将其判定为“安全”。  
  
该模块的误判暴露出以下风险：  
- **开发人员过度依赖自动代码生成，忽视人工复核；**  
  
- **系统中嵌入的漏洞可能直接进入生产环境；**  
  
- **假安全感削弱开发人员对代码安全的警惕；**  
  
- **LLM 工具链失去可信度，削弱整体安全策略。**  
  
###   
### 利用 Unicode 隐写技术实现隐蔽注入  
  
测试中最具威胁性的技术涉及 Unicode 隐写字符的使用。研究人员通过在“ignore all previous instructions”语句中插入零宽字符（Zero-Width Space）等不可见 Unicode 字符，成功将恶意指令隐藏于看似无害的普通提问中（如“法国首都是什么？”）。  
  
该方法不仅可以绕过 Llama Firewall 的静态检测，还能在多人协作、复制粘贴的开发环境中隐蔽传播。这种隐写攻击对现有自动扫描工具几乎完全不可见，构成了严重的现实安全威胁。  
### Meta 响应与社区反响  
  
Trendyol 于 2025 年 5 月 5 日向 Meta 报告了上述问题，Meta 于 6 月 3 日正式关闭该报告，标注状态为“Informative”，并未提供漏洞赏金。同样针对 Unicode 隐写技术提交至 Google 的报告也被标为重复条目处理。  
  
尽管厂商反馈冷淡，Trendyol 仍以此为契机，优化其内部 LLM 风险建模机制，并向行业分享完整案例，以提醒广大企业：在部署 AI 应用前，应进行充分红队演练和多层次风险评估。  
### 结语与建议  
  
Trendyol 的研究清楚地表明，当前主流 LLM 防护方案尚无法应对日益多样化的提示注入与隐蔽绕过策略。企业在部署此类系统前，需采纳以下建议：  
- 不应将提示过滤器作为唯一防线；  
  
- 应启用上下文感知、语言适应型检测模块；  
  
- 对代码输出必须引入人工审核与安全测试；  
  
- 识别并防范 Unicode 隐写与字符编码攻击；  
  
- 推行“零信任”式模型交互策略。  
  
随着生成式 AI 深度嵌入开发、办公、客服等核心业务流程，该类安全挑战势必成为未来网络安全领域的重中之重。唯有通过持续攻防对抗、标准建设与跨行业协作，才能真正构建安全可信的 LLM 应用生态。  
  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】DeepSeek再遭捷克封杀！](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070622&idx=1&sn=0b6e4805766d104ac954112f8872fc2c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Coinbase事件撕开加密安全最脆弱的防线](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070622&idx=2&sn=f58a0b0f5da56125d6d0c40e1e904f86&scene=21#wechat_redirect)  
  
  
  
[【安全圈】拿“123456”当密码，麦当劳6400万条求职信息存在泄露风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070622&idx=3&sn=5b53dd9b5f6d29081c504ae7e02b9dd2&scene=21#wechat_redirect)  
  
  
  
[【安全圈】ChatGPT 被绕过守护机制，泄露 Windows 产品密钥事件概述](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070608&idx=1&sn=4e5dc281a4812d0a3f756ec67d0bc633&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
