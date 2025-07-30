#  Nodejs Node.Js 异常处理不当漏洞   
 上汽集团网络安全应急响应中心   2025-05-20 15:55  
  
漏洞情报  
  
  
  
  
  
**Nodejs Node.Js 异常处理不当漏洞**  
  
  
**【 漏洞编号 】**  
  
CVE-2025-23166  
  
  
**【 情报等级 】**  
  
**中危**  
  
  
**【 漏洞描述 】**  
  
360漏洞云监测到Nodejs官方发布新版本，新版本中修复了多个安全漏洞，其中包括一个异常处理不当漏洞，可导致拒绝服务攻击。该漏洞是由于C++ 方法 SignTraits::DeriveBits () 在后台线程执行时，可能会基于用户提供的输入错误调用 ThrowException () ，从而导致 Node.js 进程崩溃。官方已经发布新版本修复此漏洞，建议受影响用户及时升级到安全版本。  
  
  
**【 影响产品 】**  
  
<table><tbody><tr style="box-sizing: border-box;"><td data-colwidth="99.0000%" width="99.0000%" style="border-width: 1px;border-color: rgb(255, 255, 255);border-style: solid;background-color: rgb(231, 231, 231);padding: 6px;box-sizing: border-box;"><section style="text-align: center;font-size: 14px;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">node,node.js,Node,nodejs nodejs,Node.js&gt;=22.0&amp;&amp;&lt;23.11.1,&gt;=22.0&amp;&amp;&lt;24.0.2,&gt;=22.0&amp;&amp;&lt;22.15.1,&gt;=20.0&amp;&amp;&lt;20.19.2</span></p></section></td></tr></tbody></table>  
  
**【 解决方案与修复建议 】**  
  
目前官方已发布安全补丁，建议受影响用户尽快升级至以下**安全版本：**  
  
Node.js >= 20.19.2  
  
Node.js >= 22.15.1  
  
Node.js >= 23.11.1  
  
Node.js >= 24.0.2  
  
**补丁下载链接：**  
  
https://nodejs.org/en/blog/release/v20.19.2/  
  
https://nodejs.org/en/blog/release/v22.15.1/  
  
https://nodejs.org/en/blog/release/v23.11.1/  
  
https://nodejs.org/en/blog/release/v24.0.2  
  
与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。  
  
