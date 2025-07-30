> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4NDg2NTM3NQ==&mid=2247484831&idx=1&sn=7375e6ef426b4fd5a0821baee05fcf67

#  【CVE‑2025‑49144】Notepad++提权漏洞  
原创 Blue17  表哥带我   2025-06-24 07:18  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/pxKqYxJWy7MHqrAcwIGH5K7UvO9SFI4EkaH4ooCVsu7cll9674CjgclKxGIKcM5MNF5s7vnK2NjZ6tliaQ0FWNg/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
#### 漏洞描述  
###   
  
Notepad++ v8.8.1 安装程序被披露存在提权漏洞  
CVE‑2025‑49144  
，非特权用户可通过不安全的可执行文件搜索路径获取系统级（SYSTEM）权限。  
#### 漏洞详情  
###   
<table><thead><tr><th><strong><span leaf="">信息类别</span></strong></th><th><strong><span leaf="">具体内容</span></strong></th></tr></thead><tbody><tr><td><strong><span leaf="">漏洞编号</span></strong></td><td><section><span leaf="">CVE-2025-49144</span></section></td></tr><tr><td><strong><span leaf="">影响软件</span></strong></td><td><section><span leaf="">Notepad++ v8.8.1 及之前版本的安装程序</span></section></td></tr><tr><td><strong><span leaf="">漏洞类型</span></strong></td><td><section><span leaf="">未受控的 EXE/DLL 搜索路径（二进制文件植入）</span></section></td></tr><tr><td><strong><span leaf="">漏洞等级</span></strong></td><td><section><span leaf="">高危（High）</span></section></td></tr><tr><td><strong><span leaf="">发布日期</span></strong></td><td><section><span leaf="">2025 年（具体日期随研究报告披露时间而定）</span></section></td></tr><tr><td><strong><span leaf="">漏洞影响</span></strong></td><td><section><span leaf="">本地权限提升至 NT AUTHORITY\SYSTEM 级别，可导致系统完全控制、数据泄露等风险</span></section></td></tr></tbody></table>###   
#### 攻击方式  
###   
<table><thead><tr><th><strong><span leaf="">攻击维度</span></strong></th><th><strong><span leaf="">具体内容</span></strong></th></tr></thead><tbody><tr><td><strong><span leaf="">攻击准备</span></strong></td><td><section><span leaf="">攻击者将恶意可执行文件（如 regsvr32.exe）放置在目标目录（如用户下载文件夹）</span></section></td></tr><tr><td><strong><span leaf="">攻击载体</span></strong></td><td><section><span leaf="">用户下载并运行 Notepad++ v8.8.1 安装程序</span></section></td></tr><tr><td><strong><span leaf="">攻击执行机制</span></strong></td><td><section><span leaf="">安装程序在当前工作目录搜索依赖项时加载恶意文件，以 SYSTEM 权限执行</span></section></td></tr><tr><td><strong><span leaf="">攻击结果</span></strong></td><td><section><span leaf="">攻击者获取系统完全控制权，可执行任意代码、窃取数据或横向移动</span></section></td></tr><tr><td><strong><span leaf="">真实攻击场景</span></strong></td><td><section><span leaf="">通过社会工程学诱使用户将恶意文件与安装程序下载至同一目录，运行后自动触发攻击</span></section></td></tr></tbody></table>###   
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7O57qSYibvCyNEmokmftcKyToeUBW3RCVBQt5gJeEqdw1aTIn0SDgmg2Eic9ricR5yN341Ypl5UiaBLDg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7O57qSYibvCyNEmokmftcKyT7xrtuzxMxEibJEuxTmq46m9AQGSq7ic0Q9SAxPrEQhMBYxsibPy8ouuKw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7O57qSYibvCyNEmokmftcKyTNiaHZyRRyoCwkn5fLxr1RqT3VsGEV8kic5sck9ZpTJ57eAFScN9ywZYQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pxKqYxJWy7O57qSYibvCyNEmokmftcKyTvYIa31cV7HrYepzArH1az9TphuCSPfsjPHF6t7UXricicAaVYdWicBicLw/640?wx_fmt=png&from=appmsg "")  
  

```
已定位问题根源：Notepad++ 存在 EXE 侧加载漏洞，因调用 regsvr32 时未指定绝对路径，导致其从当前工作目录加载恶意可执行文件。
```

  

```
ExecWait 'regsvr32 /u /s &#34;$INSTDIR\NppShell_01.dll&#34;'

```


```
ExecWait '$SYSDIR\regsvr32.exe /u /s &#34;$INSTDIR\NppShell_01.dll&#34;'
```

###   
### 修复与防护建议  
###   
<table><thead><tr><th><strong><span leaf="">防护维度</span></strong></th><th><strong><span leaf="">具体措施</span></strong></th></tr></thead><tbody><tr><td><strong><span leaf="">官方修复方案</span></strong></td><td><section><span leaf="">升级至 Notepad++ 8.8.2 及以上版本，安装程序已改用绝对路径加载依赖项（如</span><code><span leaf="">$SYSDIR\regsvr32.exe</span></code><span leaf="">）</span></section></td></tr><tr><td><strong><span leaf="">用户防护建议</span></strong></td><td><section><span leaf="">1. 从官方渠道下载安装程序，避免从非可信来源获取</span><br/><span leaf="">2. 运行安装程序前清空下载目录中的可疑文件</span><br/><span leaf="">3. 使用安全软件监控安装过程中的文件调用</span></section></td></tr><tr><td><strong><span leaf="">开发修复实践</span></strong></td><td><section><span leaf="">1. 对安装程序依赖项使用绝对路径加载</span><br/><span leaf="">2. 实施可执行文件数字签名验证</span><br/><span leaf="">3. 创建随机名称的安全临时目录</span></section></td></tr><tr><td><strong><span leaf="">参考标准</span></strong></td><td><section><span leaf="">遵循微软《安全库加载指南》</span></section></td></tr></tbody></table>####   
#### 相似漏洞  
- CVE-2023-6401 与 CVE-2023-47452（Notepad++ 旧版本漏洞）。  
  
- CVE-2024-44346（类似的二进制植入漏洞）。  
  
- 戴尔 SupportAssist 漏洞（DSA-2024-312）。  
  
Notepad++ 早年的一个公告  
  
不过以其作者的尿性，是后门也不奇怪  
  
对不支持其政治立场的用户在代码中随机插入字符  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pxKqYxJWy7O57qSYibvCyNEmokmftcKyTrialZQI8oPPU6HpOqrUuqcjBAY4k8edMicmRicdicsfHVjKs1twsLIBsRQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**违背开源精神**  
开源软件倡导自由、共享和协作，其目的是为了让全球开发者共同受益和进步。作者将个人政治立场强加于软件，并以破坏用户代码相威胁，严重违背了开源软件的本质和初衷，破坏了开源社区的信任和生态。用户使用文本编辑器是为了高效地进行代码编写、文本处理等工作。作者的行为将个人主观意志凌驾于用户之上，无视用户的权益和需求，可能会给用户带来巨大的损失，如代码出错、工作延误等  
  
  
以下是一些 Notepad++ 的平替软件  
  
  
- **Sublime Text**  
轻量、简洁、高效且跨平台。具有多重选择功能，支持宏，启动速度快，内存和  CPU 占用率低。智能代码补全功能强大，能根据代码上下文预测并提供补全建议。支持多种编程语言，语法高亮效果好，还可通过插件扩展功能，如  Emmet 可快速生成前端代码，GitGutter 能显示 Git 状态。  
  
- **Visual Studio Code**  
跨平台编辑器，针对现代 Web  和云应用开发。它有丰富的扩展生态，能满足各种开发需求，例如安装 Python 扩展可进行 Python 开发，安装 Java 扩展可进行  Java 开发等。集成了版本控制系统，方便进行代码版本管理。调试功能强大，能帮助开发者快速定位和解决代码中的问题。  
  
- **Github Atom**  
由 GitHub 专门为程序员推出的跨平台文本编辑器。界面美观、现代化，使用舒适，设置管理方便。支持各种编程语言的代码高亮和代码补全，原生支持 Git 和 Markdown，有文件树列表功能，方便多文件管理，社区活跃，插件和主题丰富。  
  
- **BowPad**  
带有功能区 UI  的简单而快速的文本编辑器，使用方便，可颜色标注重点部分，支持内嵌式编辑和代码编辑。支持多种编码格式，语法高亮功能覆盖超过 100  种文件类型和语言。其直观的 ribbon 界面让用户能迅速找到所需功能，垂直滚动条中集成导航提示，便于在长文档中定位，还可通过插件扩展功能。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/pxKqYxJWy7PZVHNNkiaicj7KnaO5w6yqAgKHGxN5p6TTJmTFGcknj1Uiac9U3B3qGYjApcPpb4BcjbqI8iax2XwqMw/640?wx_fmt=jpeg&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**扫码关注我们**  
  
微信公众号：表哥带我  
  
本文供稿：Blue17  
  
  
