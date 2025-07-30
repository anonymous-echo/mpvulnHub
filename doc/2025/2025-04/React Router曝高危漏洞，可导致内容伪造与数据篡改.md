#  React Router曝高危漏洞，可导致内容伪造与数据篡改   
白帽子左一  白帽子左一   2025-04-30 04:02  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
  
React Router 被曝严重的安全漏洞。React Router 是一个广泛使用的 React 应用路由库，这些漏洞可能允许攻击者破坏内容、污染缓存并操控预渲染数据。  
  
这些漏洞影响以 Framework 模式运行、并使用服务器端渲染（SSR）和加载器（loader）的应用程序，攻击者可远程利用漏洞，无需用户交互或权限。  
  
这两个问题已在 7.5.2 版本中修复，但在更新前，仍有数百万个应用面临风险。  
## 通过强制 SPA 模式实现缓存投毒（CVE-2025-43864）  
  
第一个漏洞的 CVSS 评分为 7.5，它使攻击者能够通过注入恶意请求头，强制服务器端渲染（SSR）应用切换为单页应用（SPA）模式。  
  
在请求中添加 X-React-Router-SPA-Mode  
 头部并访问使用 loader 的页面，会抛出错误，完全破坏页面内容。  
  
当应用使用 SSR 并被意外强制切换至 SPA 模式时，会产生严重错误，导致页面内容发生重大变更。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHQ1GyvsHicKMvT48w88IreLBFho7dRf36YG4gAMggJ8TMx4h421Fpvh35icgyB26qQU5edxRqCGBNA/640?wx_fmt=png&from=appmsg "null")  
  
  
该漏洞影响 React Router 版本 7.2.0 至 7.5.1。如果应用实现了缓存系统，被破坏的响应可能会被存储并返回给后续用户，从而有效地造成缓存投毒，并引发拒绝服务（DoS）条件。  
  
要利用此漏洞，攻击者无需任何特殊权限——只需在请求中添加恶意请求头，针对使用 loader 的页面发送请求，且这些页面运行在 Framework 模式下的 React Router 应用中。  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><strong style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-weight: bold;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: inherit;color: rgb(15, 76, 129);"><span leaf="">风险因素</span></strong></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><strong style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-weight: bold;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: inherit;color: rgb(15, 76, 129);"><span leaf="">详细信息</span></strong></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">受影响产品</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">React Router（npm 包）版本 ≥ 7.2.0，≤ 7.5.1</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">影响</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">拒绝服务（DoS）</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">利用前提条件</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">– 应用必须在 Framework 模式下使用 React Router– 目标页面必须使用 loader– 无需权限– 无需用户交互– 攻击者可通过网络请求注入 </span><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 14.4px;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">X-React-Router-SPA-Mode</span></code><span leaf=""> 请求头</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">CVSS 3.1 评分</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">7.5（高危）</span></section></td></tr></tbody></table>  
  
github上相关漏洞的本地复现过程：  
### 复现步骤  
  
PoC 使用的版本：  
- • "@react-router/node": "^7.5.0",  
  
- • "@react-router/serve": "^7.5.0",  
  
- • “react”：“^19.0.0”  
  
- • “react-dom”：“^19.0.0”  
  
- • “react-router”：“^7.5.0”  
  
在框架模式下使用默认配置安装 React-Router（ https://reactrouter.com/start/framework/installation ）  
  
使用加载器添加一个简单的页面（例如： routes/ssr  
 ）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHQ1GyvsHicKMvT48w88IreLP5w4HAXJbIBXAOIKsRBCLv21pyfmd3SjYx7mllhpq6CpZRciaoywiaqw/640?wx_fmt=png&from=appmsg "")  
  
  
  
使用加载器（在我们的例子中为 /ssr  
 ）向端点发送请求，并添加以下标头：  
```
X-React-Router-SPA-Mode: yes
```  
  
注意带有和不带有标头的请求之间的区别；  
  
**正常请求**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHQ1GyvsHicKMvT48w88IreLJ5IicDfXJXIV2olgxVocicl33bfMwgsJicWy2K431yuA47JInj4xqzQcg/640?wx_fmt=png&from=appmsg "")  
  
  
**带有标头**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHQ1GyvsHicKMvT48w88IreLyNQoYM3T9sQyKLJ0yr4Uf0GtC0ESmj50vKaHwib8NXVWsIsBsickLfIw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHQ1GyvsHicKMvT48w88IreLBQtUcNNdaqPn0d2hwmgbOAJ7V51Dq24VngCGMl4dwLqTyicb2cngxiaw/640?wx_fmt=png&from=appmsg "")  
  
  
影响：如果存在系统缓存，则可以通过完全改变其内容（   
通过错误消息  
 ）来毒害响应，从而严重影响其可用性，使得后者通过缓存中毒攻击变得不切实际。  
## 预渲染数据伪造漏洞（CVE-2025-43865）  
  
第二个漏洞更为严重，CVSS 评分为 8.2。攻击者可通过注入特制的 X-React-Router-Prerender-Data  
 请求头来操控预渲染数据。  
  
此攻击向量可实现对内容的完全伪造，通过修改传递给 HTML 的数据对象中的数值，在页面呈现给用户之前进行篡改。通过在请求中添加一个请求头，可以修改预渲染的数据，使攻击者能够完全伪造其内容，并修改传递给 HTML 的数据对象中的所有值。  
  
该漏洞影响更广泛的版本范围，从 7.0 到 7.5.1。其影响严重，可能导致：  
- • 内容被操控；  
  
- • 缓存投毒攻击；  
  
- • 若客户端数据处理方式存在问题，可能进一步导致存储型 XSS 漏洞。  
  
Framework 模式下的 React Router 提供了一种将单页应用（SPA）概念与服务器端渲染（SSR）相结合的混合方案。默认情况下启用 SSR，但可以通过在 react-router.config.ts  
 文件中设置 ssr:false  
 将其配置为运行在 SPA 模式。  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHQ1GyvsHicKMvT48w88IreLf5BEmG04cFw1LBW9vVickoDIsZpoPTD5yY1PIa9vicGvVUoib0W7y7R4A/640?wx_fmt=png&from=appmsg "null")  
  
  
这些漏洞专门针对使用 loader 的应用程序，loader 在 React Router 应用中负责数据获取。  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><strong style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-weight: bold;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: inherit;color: rgb(15, 76, 129);"><span leaf="">风险因素</span></strong></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><strong style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-weight: bold;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: inherit;color: rgb(15, 76, 129);"><span leaf="">详细信息</span></strong></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">受影响产品</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">React Router（npm 包）版本 ≥ 7.0，≤ 7.5.1</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">影响</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">使用任意数据进行缓存投毒</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">利用前提条件</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">– 应用必须在 Framework 模式下使用 React Router– 目标页面必须使用 loader– 攻击者可注入包含特制 JSON 的 </span><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 14.4px;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">X-React-Router-Prerender-Data</span></code><span leaf=""> 请求头– 无需权限或用户交互</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">CVSS 3.1 评分</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section style="text-align: left;margin-top: 8px;margin-bottom: 16px;"><span leaf="">8.2（高危）</span></section></td></tr></tbody></table>  
  
github上相关漏洞的本地复现过程：  
  
存在漏洞的标头是 X-React-Router-Prerender-Data  
 ，必须向其传递一个特定的 JSON 对象才能使欺骗成功,以下是  
存在漏洞的代码   
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHQ1GyvsHicKMvT48w88IreL0qTKO0LLLlmAJcuTtXDeLWCUKqfgoq8VianYfwFcVYo3GhU3ElpicAvA/640?wx_fmt=png&from=appmsg "")  
  
### 复现步骤  
  
PoC 使用的版本：  
- • "@react-router/node": "^7.5.0",  
  
- • "@react-router/serve": "^7.5.0",  
  
- • “react”：“^19.0.0”  
  
- • “react-dom”：“^19.0.0”  
  
- • “react-router”：“^7.5.0”  
  
在框架模式下使用默认配置安装 React-Router（ https://reactrouter.com/start/framework/installation ）  
  
使用加载器添加一个简单的页面（例如： routes/ssr  
 ）  
  
通过添加 .data  
 后缀来访问你的页面（   
使用了 loader 的页面  
 ）。在我们的例子中，该页面名为 /ssr  
 ：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHQ1GyvsHicKMvT48w88IreLicF1Tia3P42KwoCkwJArHsA06Tshpe3uErWqz9U9P8x096mpNfprxVyQ/640?wx_fmt=png&from=appmsg "")  
  
  
通过添加后缀 .data  
 来访问它并检索标题所需的数据对象：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHQ1GyvsHicKMvT48w88IreLibo2oNqflgD04cP2Obc6ibJCDGKyZ2HNDEcuSm827jibjcWZ9RcotlxWg/640?wx_fmt=png&from=appmsg "")  
  
  
通过添加 X-React-Router-Prerender-Data  
 标头来发送请求，并将之前检索到的对象作为其值。您可以更改 data  
 对象的任何值（请勿修改其他值，因为其他值是正确处理对象且不抛出错误的必要条件）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSHQ1GyvsHicKMvT48w88IreL74En8bv3zpWCGTHumM7dJ7lt9lJicUPDicZUuSHHKnw0YGia6icic1j3cEQ/640?wx_fmt=png&from=appmsg "")  
  
  
如图所见，所有值都已被通过标题提供的值更改/覆盖。  
  
影响：如果缓存系统已经到位，攻击者就有可能毒害响应，导致通过加载器传输的所有数据被攻击者篡改，从而控制页面内容，并通过缓存中毒攻击随意修改。这可能导致多种类型的攻击，包括潜在的存储型 XSS，具体取决于数据注入的上下文和/或数据在客户端的使用方式。  
## 修复措施  
  
这两个漏洞已在 2025 年 4 月 24 日发布的 React Router 版本 7.5.2 中修复。React Router 团队强烈建议所有用户立即升级，以降低安全风险。  
  
使用 React Router 的组织应当：  
- • 立即升级至 7.5.2 或更高版本；  
  
- • 如果使用了自定义缓存机制，应实施合理的请求头验证；  
  
- • 检查应用日志，查找包含这些恶意请求头的潜在利用行为；  
  
- • 考虑实施内容安全策略（CSP），以提供额外的防护。  
  
鉴于 React Router 在网页应用中的广泛使用，这些漏洞构成了严重的安全隐患，开发团队需立即引起重视并采取应对措施。  
  
参考：  
  
https://cybersecuritynews.com/react-router-vulnerabilities/  
  
https://github.com/advisories/GHSA-cpj6-fhp6-mr6j  
  
   
  
获取更多精彩内容，尽在Track安全社区~：  
https://bbs.zkaq.cn  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
****  
  
