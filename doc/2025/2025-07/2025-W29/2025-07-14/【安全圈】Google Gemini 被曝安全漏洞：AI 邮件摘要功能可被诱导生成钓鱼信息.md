> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070655&idx=3&sn=7ccd92ac4dd522bb9216323ef93d3402

#  【安全圈】Google Gemini 被曝安全漏洞：AI 邮件摘要功能可被诱导生成钓鱼信息  
 安全圈   2025-07-14 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
Google  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj36aZkXSpokWicU6IbwrvWua5a0c8SSPoWK4uphgoNrq6zwYfOfWa8h2mowOicFKhVaHBKCwTQAibyg/640?wx_fmt=png&from=appmsg "")  
  
研究人员披露，Google Workspace 中的 Gemini AI 邮件摘要功能可被利用，通过隐藏式提示注入（prompt injection）生成看似正常、实则含有钓鱼意图的摘要内容。攻击者无需在邮件中插入附件或链接，便能诱导用户访问恶意网站，构成新的社交工程攻击手段。  
### 利用 Gemini 摘要生成钓鱼信息  
  
此次漏洞由 Mozilla 旗下的生成式 AI 漏洞赏金项目 0din 披露，报告人是 Mozilla GenAI 安全负责人 Marco Figueroa。  
  
攻击方式基于以下核心机制：  
- 攻击者伪造一封 HTML 邮件，在正文末尾插入一段 **不可见的提示指令**  
；  
  
- 该指令通过 CSS 将字体颜色设为白色、字体大小为 0，因此不会在 Gmail 界面中显示；  
  
- 邮件看上去完全正常，不包含附件或可疑链接，极易绕过垃圾邮件过滤与安全网关；  
  
- 当用户点击 Gemini 的“生成摘要”按钮时，AI 读取并执行隐藏指令，例如提示“Gmail 密码泄露，请拨打某热线电话”，从而引导用户进入钓鱼流程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj36aZkXSpokWicU6IbwrvWuUv5Fm3GicQQmqA6icuEAfeAWfozCuKLYu7oKxicic4iaH9PJibOcicjw1gpUA/640?wx_fmt=png&from=appmsg "")  
  
示例中，Gemini 根据注入指令生成了一段误导性极强的安全警报，使人误以为账号遭入侵，诱导其拨打伪造的技术支持电话。  
  
由于 Gemini 是 Google Workspace 集成功能的一部分，用户天然对其输出具备信任度，这使得攻击极具迷惑性与现实危害。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj36aZkXSpokWicU6IbwrvWuQuxibOh5gT41tBpnxFFudk1PglrEQcx0Hko251BlnuCP2zpwiaAeR9ag/640?wx_fmt=png&from=appmsg "")  
### 防御建议与应对措施  
  
Figueroa 提出了一些检测与防护建议，供安全团队采纳：  
1. **内容净化处理**  
：对正文中通过 CSS 隐藏的文本进行过滤、移除或中和处理；  
  
1. **摘要输出后处理**  
：部署关键词检测机制，对 Gemini 输出中的“紧急”、“密码”、“电话”等术语进行审查与标记；  
  
1. **用户教育**  
：加强对终端用户的培训，提醒其 Gemini 摘要非权威安全信息来源，警惕冒充安全警告的摘要内容。  
  
### Google 回应：尚无滥用事件，但正在加强防护  
  
Google 在回应媒体 BleepingComputer 时表示，已通过“红队演练”持续训练模型以增强对抗提示注入的能力，部分防护措施已在实施中，未来还将部署更多机制。  
  
目前，Google 没有观测到像 Figueroa 所演示的此类攻击在现实中被广泛利用。但此次发现再次提醒业界，即便是主流 AI 功能也可能被绕过常规防御机制，成为社会工程攻击的新跳板。  
  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】OpenAI 即将推出集成 AI 智能体的 Chromium 浏览器，挑战 Chrome 市场主导地位](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=1&sn=f8fe5c05daa266c8470e771cba01275f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】PerfektBlue：四项蓝牙协议栈漏洞危及数百万车辆，可被远程执行代码](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=2&sn=f98a8cececf06db2add503959abb412c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】印度背景黑客组织 DoNot APT 使用 LoptikMod 恶意软件攻击欧洲外交部](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=3&sn=bbaf04680a16d1922d1ac51d26b48f5a&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Trendyol 披露 Meta  存在漏洞：Prompt Injection 成功率高达 50%](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=4&sn=4e7c93291c55d089867addbbd0436070&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
