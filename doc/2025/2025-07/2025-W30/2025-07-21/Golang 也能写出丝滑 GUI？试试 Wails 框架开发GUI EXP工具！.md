> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0MzUwNDEzNg==&mid=2247484305&idx=1&sn=74f8bcf6726c3f25573c3c11d5c7f338

#  Golang 也能写出丝滑 GUI？试试 Wails 框架开发GUI EXP工具！  
逗逗  0x33 SEC   2025-07-21 15:14  
  
   
  
# Golang 也能写出丝滑 GUI？试试 Wails 框架开发GUI EXP工具！  
## 前言:  
  
     在 Golang 生态中，常见的桌面 GUI 框架包括 Fyne、Lorca、Walk、gioui 等。而 **Wails**  
 在开发效率与最终应用体验之间，找到了很好的平衡点。  
  
       
Golang 在渗透测试工具开发领域表现尤为出色，甚至被称为“黑客语言”。在接触 Go 之前，我主要用 Python 编写自动化工具。但自从熟悉 Go 后，我几乎完全转向了它。  
  
       
相比 Python，Go 最大的优势是  
天然的跨平台支持（一次编写，到处运行）  
和  
对高并发的原生支持  
——没错，我就是 Go 吹！  
  
       
像   
projectdiscovery  
 这个组织，就维护了众多基于 Go 的渗透测试利器：
```
httpx
```

  
、
```
nuclei
```

  
、
```
naabu
```

  
、
```
katana
```

  
 等。这些工具我在日常工作中经常使用，也充分证明了 Go 在安全工具开发中的适配性与高效性。  
  
### Go语言编写GUI程序的痛点:  
  
       
虽然 Go 在后端和工具开发上表现出色，但在 GUI 开发上却长期存在短板：  
- • **生态薄弱**  
：主流框架少，很多项目维护不活跃  
  
- • **开发效率低**  
：界面需用纯 Go 手写，代码繁琐  
  
- • **缺乏设计器**  
：无可视化工具，开发体验差  
  
       
很多 Golang GUI 框架的文档**一眼难尽**  
(写了，但没写全，看了，但不想看第二眼。)，内容零散、例子稀少，读起来像在解谜。很久之前尝试过使用Fyne来开发GUI程序，最终放弃了。  
  
### 什么是 Wails？  
  
**Wails**  
 是一个专为 Go 开发者设计的桌面应用框架，它允许你用 **Go 编写后端逻辑**  
，同时使用 **HTML/CSS/JavaScript 构建前端界面**  
。  
  
       
Wails 的设计理念是将现代 Web 前端的开发体验与 Go 的高性能结合在一起，让 Go 开发者也能轻松构建界面精美、跨平台的桌面应用。  
#### Wails对比其它框架  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">框架</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">UI 技术</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">跨平台</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">适合场景</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Wails</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Web 前端 + Go</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">✅</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">工具类、小型桌面应用</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Fyne</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">纯 Go</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">✅</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Go-only 项目、内部工具</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Walk</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Windows API 封装</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">❌</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Windows 工具开发</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">gioui</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">OpenGL 自绘</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">✅</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">图形类应用、实验项目</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Lorca</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Chrome 驱动 Web</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">✅</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">停止维护，不推荐</span></section></td></tr></tbody></table>  
#### Wails 的实现原理  
- • **Web 前端渲染**  
：使用系统的 WebView（如 macOS 的 WebKit、Windows 的 Edge/Chromium WebView2）展示 UI  
  
- • **Go 后端服务**  
：通过 RPC 通信桥梁，将前端事件映射到 Go 的方法调用（通过 
```
Bind()
```

  
 进行函数绑定）  
  
- • **打包构建**  
：前端代码先构建为静态资源（
```
dist/
```

  
），再由 Go 的 
```
embed.FS
```

  
 打包进最终程序  
  
## 基本使用:  
### 一、安装:  

```
go install github.com/wailsapp/wails/v2/cmd/wails@latest
```

### 二、初始化Wails项目  

```
wails init -n PortScan
```

  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/l7pUdib7P7lt37EkOVJKTNDjV0qhaV8IgEenSggECGxbj52rX0GvLzib7zUR0o4ibURtgL0X4wHVPF9VicZB35YQTg/640?wx_fmt=png&from=appmsg "")  
  

```
PortScan/
├── frontend/         ← 前端源码（HTML/JS/CSS）
├── main.go           ← 主程序入口
├── go.mod
└── wails.json        ← 配置文件
```

#### 常用命令:  

```
wails init       # 创建新项目
wails dev        # 开发运行模式
wails build      # 构建生产包
wails doctor     # 检查依赖环境
```

#### Wails调用Go方法的流程:  
  
前端 JS → 通过 Wails 自动生成的 JS SDK → 调用 Go 方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/l7pUdib7P7lt37EkOVJKTNDjV0qhaV8IgI4CHNp3PqhMOicHNibupQzQL0YvVAJfxEfJTvmfqibsAlVznjibFuBdHaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/l7pUdib7P7lt37EkOVJKTNDjV0qhaV8IgzfAppMTbR8ZKWr6YVtIwX5OWibfcFbtkx8icFRiazo2jf4ul8G1Yo7grQ/640?wx_fmt=png&from=appmsg "")  
  
#### Demo运行效果:  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/l7pUdib7P7lt37EkOVJKTNDjV0qhaV8Ig4jv5k7VnVrMDZdqIFic6NorCYbRRiafBMIUS9Jq0NZHsgxwniciaguOribg/640?wx_fmt=png&from=appmsg "")  
  
## GUI漏洞利用工具  
  
       
这里以Vulhub的Thinkphp 5-rce、5.0.23-rce，为例编写一个GUI漏洞利用Demo。  
  
       
效果还行，感觉比基于Fyne写的好看些，但Wails毕竟基于前端的方式调用Go方法，所以只适合开发轻量级的GUI程序。  
  
       
源码项目地址在文末，Demo只实现了简单的命令执行，你可以基于这个代码继续改进，这里只做演示。  
  
  
代码仓库:  
  
      
       
https://github.com/80r1ng/ThinkPHP-Exploit-Demo  
  
   
  
### 免责声明  
  
       
由于传播或利用本公众号**0x33**  
所提供的信息而产生的任何直接或间接后果与损失，均由使用者本人负责。公众号**0x33**  
及作者不承担任何相关责任。如因内容涉及侵权，烦请及时告知，我们会尽快删除并向您致以诚挚的歉意。感谢您的理解与支持！  
  
   
  
  
   
  
