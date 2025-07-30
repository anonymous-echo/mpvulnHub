#  提示词宝库！NucleiPrompts 助你轻松玩转 Nuclei AI智能漏洞扫描   
原创 AI安全工坊  AI安全工坊   2025-04-23 05:16  
  
## 引言：Nuclei AI智能化扫描！  
  
Nuclei 是一款超好用的漏洞扫描工具，而 NucleiPrompts.com 则像它的“金牌助手”，通过分享现成的提示词（Prompts），让扫描漏洞变得像点外卖一样简单！  
  
想知道怎么用一句话找到网站隐患？快来跟我们一起探索这个“提示词宝库”，零基础也能玩转网络安全！  
## 一、NucleiPrompts.com 是什么？  
  
1.1 提示词分享的“懒人神器”  
  
NucleiPrompts.com 是一个专门为 Nuclei 工具打造的提示词分享网站。Nuclei 是一款能帮你扫描网站漏洞的开源工具，比如检查有没有 XSS 攻击、泄露的文件等。而 NucleiPrompts.com 就像一个“秘籍大全”，收集了大家贡献的提示词，让你直接复制粘贴，就能让 Nuclei 干活！  
  
它能干啥？  
  
•  
现成提示词：提供各种漏洞的提示词，比如“找暴露的配置文件”。  
•  
社区互助：大家分享自己的“独门秘籍”，你也能上传你的创意。  
•  
简单上手：不用写复杂代码，复制提示词就能用。  
  
1.2 比自己摸索强在哪儿？  
  
直接用 Nuclei 需要自己琢磨怎么写提示词，费时又费脑。NucleiPrompts.com 的优势是：  
  
•  
省时间：社区的提示词已经试过好用，直接拿来用。  
•  
超方便：不用懂技术，复制粘贴就行。  
•  
灵感多：看看别人的提示词，轻松学会新玩法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BibeFvVBkRAicXEzODiaKJzOiaBLQMrmtrvuMOFCjfLDQsAYEBSBhTFJQR4FUibeHfV0JNmofkHbwzjbvP6rLfGs8MQ/640?wx_fmt=png&from=appmsg "")  
## 二、为啥要用 NucleiPrompts.com？  
  
2.1 一句话，漏洞无处藏  
  
想知道网站有没有泄露重要文件？在 NucleiPrompts.com 找个提示词，比如：  
  
“检查网站有没有暴露 .env 文件”  
  
复制到 Nuclei 工具，运行命令：  
```
nuclei -list targets.txt -ai "Check for exposed .env files"
```  
  
几分钟后，扫描结果告诉你哪儿有问题！完全不用自己写代码POC，省心又高效。  
  
2.2 啥漏洞都能查  
  
NucleiPrompts.com 上的提示词覆盖了各种常见漏洞：  
  
•  
XSS（跨站脚本）：防恶意脚本偷用户数据。  
•  
泄露文件：找暴露的配置文件，比如 WordPress 的设置文件。  
•  
权限漏洞：查有没有能被黑客钻空子的地方。  
•  
高危漏洞：发现可能让黑客控制服务器的严重问题。  
  
不管是保护自己的网站，还是帮朋友检查安全，这些提示词都超实用！  
## 三、三步搞定漏洞扫描！  
  
3.1 准备工作  
  
开始前，你需要：  
  
1.  
装好 Nuclei：去 GitHub（https://github.com/projectdiscovery/nuclei）下载，跟着教程装一下。  
2.  
拿个密钥：在 ProjectDiscovery 网站（cloud.projectdiscovery.io）注册，领个免费密钥。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BibeFvVBkRAicXEzODiaKJzOiaBLQMrmtrvuaeTbvSQOOtU7ALdKHxbWK5MX3fjicRicuwhBGeOsrzNSiamiceOJWp1e6Q/640?wx_fmt=png&from=appmsg "")  
  
打开终端运行下面命令  
```
nuclei -auth
```  
  
输入上面获取的API-KEY即可。  
  
1.  
联网：提示词需要联网用。  
  
3.2 超简单操作  
  
1.  
逛网站：打开 https://nucleiprompts.com，翻翻漏洞分类（比如“文件泄露”）。  
2.  
挑提示词：选个现成的提示词，或者自己写一句（像“找 WordPress 登录漏洞”）。  
3.  
跑扫描：把提示词粘到 Nuclei 命令行，运行：  
```
nuclei -list targets.txt -ai "Find WordPress login vulnerabilities"
```  
  
运行结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BibeFvVBkRAicXEzODiaKJzOiaBLQMrmtrvuATm6ZRyYKJdqQBJPJWV6mbTsdwMyayIFWTxWnbLsgRbwnlGYTMwQCg/640?wx_fmt=png&from=appmsg "")  
  
AI生成的POC 地址在终端显示了访问地址，在线访问后显示AI生成的POC，本地也会生成在 nuclei-template/pdcp 文件夹目录下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BibeFvVBkRAicXEzODiaKJzOiaBLQMrmtrvusTiaKKl86ic48AEgkh1RWpPemw5SoQhw5eRudIic8MA7Y44YG7MqvaBqw/640?wx_fmt=png&from=appmsg "")  
  
3.3 小提醒  
  
•  
每天限额：免费用户一天能跑 100 次，够用了！  
•  
合法第一：只扫自己有权限的网站，别惹麻烦。  
•  
试试改词：提示词不完美？稍微改改，效果更好。  
## 五、结尾：AI漏扫从现在开始！  
  
NucleiPrompts.com 就像漏洞扫描的“ cheat code”，让 Nuclei 用起来又快又顺手！  
  
快去试试：  
  
1.  
打开 https://nucleiprompts.com，找个提示词玩玩！  
2.  
关注AI安全工坊公众号，学更多AI安全小技巧！  
3.  
评论区聊聊：你用 NucleiPrompts 找到啥漏洞了？  
  
  
  
## AI安全工坊内部社群  
  
  
  
**🔥 AI安全工坊社群 · 6大核心价值 🔥**  
1. **AI安全实战**  
→ AI渗透测试 | 模型加固 | 数据防护 | 模型测评  
  
1. **开发全栈指南**  
→ 大模型应用 | Agent开发 | 行业解决方案 | AI安全工具 | AI产品开发  
  
1. **商业落地加速**  
→ 案例拆解 | ROI优化 | 合规指南  
  
1. **专属学习支持**  
→ 文档库 | 答疑 | 代码示例 | 1v1 解答  
  
1. **独家资源网络**  
→ 工具包 | 漏洞库 | 行业报告 | AI视频课程 | AI多模态资源  
  
1. **高质量AI社群**  
→ 技术交流 | 内推机会 | 项目合作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BibeFvVBkRAicHn7IC6WXiaPEfumEvmO15U6l7p2efUz1oia0ugSlK5FwtEbMNcUMoGOt3hoSNfibSmiaNtFu80V138g/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
## 福利赠送  
  
  
  
**公众号后台私信消息发送**  
如下关键词获取专属免费工具和教程：  
<table><tbody><tr><td data-colwidth="268" width="268" valign="top" style="word-break: break-all;"><section><span leaf="">序号</span></section></td><td data-colwidth="268" width="268" valign="top" style="word-break: break-all;"><section><span leaf="">关键词</span><span style="display: none;line-height: 0px;"><span leaf="">‍</span></span><span style="display: none;line-height: 0px;"><span leaf="">‍</span></span></section></td></tr><tr><td data-colwidth="268" width="268" valign="top" style="word-break: break-all;"><section><span leaf="">1</span></section></td><td data-colwidth="268" width="268" valign="top" style="word-break: break-all;"><span style="color: rgb(26, 27, 28);font-family: -apple-system, system-ui, &#34;system-ui&#34;, &#34;PingFang SC&#34;, &#34;SF Pro Text&#34;, &#34;Helvetica Neue&#34;, Helvetica, &#34;Hiragino Sans GB&#34;, &#34;Heiti SC&#34;, Arial, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, sans-serif;font-size: 14px;letter-spacing: normal;text-align: left;background-color: rgb(255, 255, 255);"><span leaf="">AI大模型安全评估标准和指南</span></span></td></tr><tr><td data-colwidth="268" width="268" valign="top" style="word-break: break-all;"><section><span leaf="">2</span></section></td><td data-colwidth="268" width="268" valign="top" style="word-break: break-all;"><span style="color: rgb(26, 27, 28);font-family: -apple-system, system-ui, &#34;system-ui&#34;, &#34;PingFang SC&#34;, &#34;SF Pro Text&#34;, &#34;Helvetica Neue&#34;, Helvetica, &#34;Hiragino Sans GB&#34;, &#34;Heiti SC&#34;, Arial, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, sans-serif;font-size: 14px;letter-spacing: normal;text-align: left;background-color: rgb(255, 255, 255);"><span leaf="">智擎 - AI业务场景提示词生成器</span></span></td></tr><tr><td data-colwidth="268" width="268" valign="top" style="word-break: break-all;"><section><span leaf="">3</span></section></td><td data-colwidth="268" width="268" valign="top" style="word-break: break-all;"><span style="color: rgb(26, 27, 28);font-family: -apple-system, system-ui, &#34;system-ui&#34;, &#34;PingFang SC&#34;, &#34;SF Pro Text&#34;, &#34;Helvetica Neue&#34;, Helvetica, &#34;Hiragino Sans GB&#34;, &#34;Heiti SC&#34;, Arial, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, sans-serif;font-size: 14px;letter-spacing: normal;text-align: left;background-color: rgb(255, 255, 255);"><span leaf="">AI医疗助手-AI安全工坊</span><span style="display: none;line-height: 0px;"><span leaf="">‍</span></span></span></td></tr><tr><td data-colwidth="268" valign="top" style="word-break: break-all;"><section><span leaf="">4</span></section></td><td data-colwidth="268" valign="top" style="word-break: break-all;"><span style="color: rgb(26, 27, 28);font-family: -apple-system, system-ui, &#34;system-ui&#34;, &#34;PingFang SC&#34;, &#34;SF Pro Text&#34;, &#34;Helvetica Neue&#34;, Helvetica, &#34;Hiragino Sans GB&#34;, &#34;Heiti SC&#34;, Arial, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, sans-serif;font-size: 14px;letter-spacing: normal;text-align: left;background-color: rgb(255, 255, 255);"><span leaf="">AI 智能体商业应用全景图</span></span></td></tr><tr><td data-colwidth="268" valign="top" style="word-break: break-all;"><section><span leaf="">5</span></section></td><td data-colwidth="268" valign="top" style="word-break: break-all;"><span style="color: rgb(26, 27, 28);font-family: -apple-system, system-ui, &#34;system-ui&#34;, &#34;PingFang SC&#34;, &#34;SF Pro Text&#34;, &#34;Helvetica Neue&#34;, Helvetica, &#34;Hiragino Sans GB&#34;, &#34;Heiti SC&#34;, Arial, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, sans-serif;font-size: 14px;letter-spacing: normal;text-align: left;background-color: rgb(255, 255, 255);"><span leaf="">DeepSeek离线部署资源包</span></span></td></tr><tr><td data-colwidth="268" valign="top" style="word-break: break-all;"><section><span leaf="">6</span></section></td><td data-colwidth="268" valign="top" style="word-break: break-all;"><span style="color: rgb(26, 27, 28);font-family: -apple-system, system-ui, &#34;system-ui&#34;, &#34;PingFang SC&#34;, &#34;SF Pro Text&#34;, &#34;Helvetica Neue&#34;, Helvetica, &#34;Hiragino Sans GB&#34;, &#34;Heiti SC&#34;, Arial, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, sans-serif;font-size: 14px;letter-spacing: normal;text-align: left;background-color: rgb(255, 255, 255);"><span leaf="">AIPOC</span></span></td></tr></tbody></table>- 免责声明  
  
   
  
  
  
