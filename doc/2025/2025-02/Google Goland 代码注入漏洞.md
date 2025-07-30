#  Google Goland 代码注入漏洞   
 上汽集团网络安全应急响应中心   2025-02-14 15:55  
  
**漏洞情报**  
  
  
  
  
  
**Google  Goland 代码注入漏洞**  
  
  
**【 漏洞编号 】**  
  
CVE-2025-22867  
  
  
**【 情报等级 】**  
  
**高危**  
  
  
**【 漏洞描述 】**  
  
360漏洞云监测到Goland官方发布安全公告，其中公开了一个代码注入漏洞，在Darwin平台上，构建一个包含CGO的Go模块，当使用Apple版本的ld时，可能会由于在"#cgo LDFLAGS"指令中使用@executable_path、@loader_path或@rpath特殊值而触发任意代码执行。  
  
  
**【 影响产品 】**  
  
<table><tbody><tr><td colspan="1" rowspan="1" style="border-color: rgb(255, 255, 255);background-color: rgb(231, 231, 231);padding: 6px;" width="99.0000%"><section style="text-align: center;font-size: 14px;"><p>Golang,golang,Go,go,google go&gt;=go1.24.0-rc.2&amp;&amp;</p></section></td></tr></tbody></table>  
  
**【 解决方案与修复建议 】**  
  
厂商已发布补丁修复漏洞，建议下载相关补丁或联系厂商获取相关支持尽快更新至安全版本。  
  
**安全版本**：  
Goland >= Go 1.24rc3  
  
与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。  
  
