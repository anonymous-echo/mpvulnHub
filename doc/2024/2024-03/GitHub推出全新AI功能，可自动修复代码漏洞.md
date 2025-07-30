#  GitHub推出全新AI功能，可自动修复代码漏洞   
 网络安全应急技术国家工程中心   2024-03-22 15:29  
  
近日，GitHub 推出了一项新的 AI 功能，能够有效提升编码时的漏洞修复速度。目前该功能已进入公开测试阶段，并在 GitHub 高级安全（GHAS）客户的所有私有软件源中自动启用。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibv3tNibwgWARibd7icfHu3ibwD4ib0OU3c2D3809OX13XJfdzMRMNLs1oAv5ImOyEsNLYfDYQPKg41vNQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
该功能名为代码扫描自动修复，可利用 Copilot 与 CodeQL（注：CodeQL 是 GitHub 开发的代码分析引擎，用于自动执行安全检查）发现你的代码中可能存在漏洞或错误，并且对其进行分类和确定修复的优先级。可帮助处理 JavaScript、Typescript、Java 和 Python 中超过 90% 的警报类型。  
  
值得一提的是，“代码扫描”需要消耗 GitHub Actions 的分钟数。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibv3tNibwgWARibd7icfHu3ibwDCrSGic63UIUg7pH0baPrkLYMs7lZZnV5LhoKAllzEDdl5XzpeTEg8dQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
据介绍，“代码扫描”还可防止开发者引入新问题，还支持在特定日期和时间进行扫描，或在存储库中发生特定事件（例如推送）时触发扫描。  
  
如果 AI 发现你的代码中可能存在漏洞或错误，GitHub 就会在仓库中进行告警，并在用户修复触发警报的代码之后取消告警。  
  
要监控你的仓库或组织的“代码扫描”结果，你可以使用 web 挂钩和 code scanning API。此外，“代码扫描”也可与输出静态分析结果交换格式 (SARIF) 数据的第三方代码扫描工具互操作。  
  
目前，对“代码扫描”使用 CodeQL 分析有三种主要方法：  
- 使用默认设置在存储库上快速配置对“代码扫描”的 CodeQL 分析。默认设置自动选择要分析的语言、要运行的查询套件和触发扫描的事件，如果需要也可以手动选择要运行的查询套件以及要分析的语言。启用 CodeQL 后，GitHub Actions 将执行工作流运行以扫描代码。  
  
- 使用高级设置将 CodeQL 工作流添加到存储库。这会生成一个可自定义的工作流文件，该文件使用 github / codeql-action 运行 CodeQL CLI。  
  
- 直接在外部 CI 系统中运行 CodeQL CLI 并将结果上传到 GitHub。  
  
GitHub 的 Pierre Tempel 和 Eric Tooley 表示：出现漏洞时，修复建议将包括对建议修复的自然语言解释，以及代码建议的预览，开发人员可以接受建议、编辑或驳回。该功能提供的代码建议和解释可以包括对当前文件、多个文件和当前项目依赖关系的修改。采用这种方法可以大大降低安全团队每天必须处理的漏洞频率。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibv3tNibwgWARibd7icfHu3ibwD0OSdsS5X85KafFPCLia7tzAXXQn0hJ0tNzW8pq89sNXu2eicc1bVlsgg/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
GitHub 承诺，这一 AI 系统可以修复其发现的三分之二以上的漏洞，所以一般来说开发人员无需主动编辑代码。该公司还承诺，代码扫描自动修复将覆盖其支持的语言中超过 90% 的告警类型，目前包括 JavaScript、Typescript、Java 和 Python。该公司计划在未来几个月内增加对其他语言的支持，下一步将支持 C# 和 Go。  
  
不过，还需要注意的是，开发人员应始终核实安全问题是否已得到解决，因为 GitHub 的 AI 功能很可能会建议仅部分解决安全漏洞的修复方法，或无法保留预期的代码功能。  
  
Tempel和Tooley补充道：代码扫描自动修复功能使开发人员在编写代码时更容易修复漏洞，从而帮助企业减缓这种 "应用程序安全债务 "的增长。  
  
上个月，该公司还为所有公共源默认启用了推送保护功能，以防止在推送新代码时意外暴露访问令牌和API密钥等机密。  
  
**参考资料：**  
  
https://www.bleepingcomputer.com/news/security/githubs-new-ai-powered-tool-auto-fixes-vulnerabilities-in-your-code/  
  
  
  
原文来源  
：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
