#  Chrome 扩展程序利用关键字操纵漏洞   
原创 很近也很远  网络研究观   2025-01-11 15:56  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxOjcHWTE8sibDAS9JlcYYUdg1M9ezcFSjdcSbokw2bqLTKPWcn0KuLib6e3eFiaOaRkct0HHc4NpXoAw/640?wx_fmt=png&from=appmsg "")  
  
Wladimir Palant 最近的调查显示，许多 Chrome Web Store 扩展程序利用漏洞，通过使用误导性描述和不相关的关键字来操纵搜索排名。  
  
  
这种策略用不相关或可疑的扩展程序扰乱搜索结果，而合法扩展程序则被埋没在不相关的列表中。  
  
### 语言漏洞  
###   
  
这种操纵取决于 Chrome Web Store 的多语言支持。  
  
  
开发人员可以使用 Chrome 支持的 55 种语言中的任何一种为其扩展程序指定本地化描述。  
  
  
有些开发人员利用这一点，在斯瓦希里语或爱沙尼亚语等较少使用的语言字段中塞入针对竞争对手或热门术语的关键字。  
  
  
这些关键词随后会影响全球的搜索结果，即使是英语等不相关的语言。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxOjcHWTE8sibDAS9JlcYYUdgBBSpOMG1ic9ibhO4OuBSt7Nl4QhBibaUiaRvT4qg0C1xKdAPh0YeVNNJug/640?wx_fmt=png&from=appmsg "")  
  
palant.info描述中使用的斯瓦希里语  
  
  
例如，搜索“Norton Password Manager”最初会在顶部显示不相关的扩展，例如 VPN 和折扣查找器，而合法的 Norton 扩展则被埋在最后。  
  
  
扩展程序采用各种方法来操纵 Chrome 网上应用店的搜索结果：  
  
1. 扩展会在各个语言中改变其名称以包含流行或竞争的术语。  
1. 特定语言的描述中添加了长串不相关的关键词。  
1. 使用不完整或无意义的翻译，通常包含大段不相关的英文文本。  
1. 使用竞争产品名称来劫持搜索可见性。  
1.   
尽管谷歌的政策明确禁止垃圾邮件和滥用行为，但执行力度却很松懈。  
  
  
其中一些滥用行为早在 2023 年就被举报，谷歌也做出了一些调整，但问题仍然存在。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yvLFKBRPQxOjcHWTE8sibDAS9JlcYYUdgKqnsaZhtAug86VjESM8DiczyaMtL65PBJAdpiaISVm8ahDzXLmw3p2RQ/640?wx_fmt=jpeg&from=appmsg "")  
  
搜索结果顺序如何随语言变化  
  
  
Chrome 网上应用店滥用者  
### 对 920 多个可疑扩展的分析揭示了采用此策略的开发人员的不同集群：  
###   
- **Kodice LLC/Karbon Project LP/BroCode LTD**：  
-   
- 这些俄语开发人员自 2023 年以来就以向 Chrome 网上应用店发送垃圾邮件而闻名，他们使用误导性的名称、描述和关键字。  
-   
- 他们的一些扩展程序与间谍软件和联盟欺诈有关。  
-   
- **PDF 工具箱集群**：  
-   
- 该组织最初于 2023 年被标记，因劫持搜索和重定向用户而受到攻击，该组织在新的扩展中使用混淆代码继续进行类似操作。  
-   
- **ZingFront Software/ZingDeck/BigMData**：  
-   
- 这家总部位于中国的公司由百度风投支持，拥有超过 223 个扩展。它通过基于订阅的高级功能利用 AI 实现盈利。  
-   
- **其他群组**：ExtensionsBox、Lazytech 和 Yue Apps 等群组的运作方式类似，通常与讲中文的开发人员有关。  
-   
研究员Wladimir Palant 建议将搜索限制在用户选择的语言范围内，以消除关键词填充，对已知集群进行定期审核，并惩罚那些一再利用漏洞的开发人员。  
  
  
关于用户在当前情况下可以做些什么来保证安全，建议在安装 Chrome 附加组件之前验证开发人员并阅读用户评论，避免授予过多的权限，并将可疑的扩展程序通知 Google。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxOjcHWTE8sibDAS9JlcYYUdg8diblO16V1acBTDan5NP5qbMicqibSsPaKj0FfLjPtW6XuId8cMHFh7pA/640?wx_fmt=png&from=appmsg "")  
  
扩展程序如何欺骗 CWS 搜索  
  
https://palant.info/2025/01/08/how-extensions-trick-cws-search/  
  
