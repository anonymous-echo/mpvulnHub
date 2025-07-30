#  【漏洞预警】Node.Js 异常处理不当漏洞   
cexlife  飓风网络安全   2025-05-15 09:06  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02Dicy8CJSp4dPcsRhXGk9PAeicUP0u2icCe8zH2qYu8JHEACe87mFJriauRqvMjy5qDboPuDuOLrRWcQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞预警:  
  
Nodejs官方发布新版本,新版本中修复了多个安全漏洞,其中包括一个异常处理不当漏洞可导致拒绝服务攻击,该漏洞是由于C++方法SignTraits::DeriveBits () 在后台线程执行时,可能会基于用户提供的输入错误调用ThrowException(),从而导致Node.js进程崩溃,官方已经发布新版本修复此漏洞,建议受影响用户及时升级到安全版本。  
  
影响版本:  
  
20.0<=OpenJS 基金会 Node.js<20.19.2  
  
22.0<=OpenJS 基金会 Node.js<22.15.1  
  
22.0<=OpenJS 基金会 Node.js<23.11.1  
  
22.0<=OpenJS 基金会 Node.js<24.0.2  
  
修复建议:  
  
目前官方已发布安全补丁,建议受影响用户尽快升级至以下安全版本:  
  
Node.js >= 20.19.2  
  
Node.js >= 22.15.1  
  
Node.js >= 23.11.1  
  
Node.js >= 24.0.2  
  
补丁下载链接:  
  
https://nodejs.org/en/blog/release/v20.19.2/  
  
https://nodejs.org/en/blog/release/v22.15.1/  
  
https://nodejs.org/en/blog/release/v23.11.1/  
  
https://nodejs.org/en/blog/release/v24.0.2  
  
与此同时,请做好资产自查以及预防工作,以免遭受黑客攻击。  
  
参考链接:  
```
```  
  
  
  
