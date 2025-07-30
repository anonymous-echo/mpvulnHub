#  一处价值 $2500 的 DOM XSS 漏洞   
原创 骨哥说事  骨哥说事   2025-05-29 16:01  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4389  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
# 概述  
  
安全研究员 gamer7112 通过利用配置错误的 postMessage 处理器，在 Upserve 的登录页面（https://inventory.upserve.com/login/  
）上发现了一个基于 DOM 的 XSS 漏洞。  
  
该漏洞源于弱 origin 验证逻辑，从而导致可以通过 eval()  
 执行攻击者控制的 JavaScript，白帽小哥最终获得 2500 美元的赏金奖励。  
# 漏洞详情  
  
易受攻击的端点：  
  
https://inventory.upserve.com/login/  
  
易受攻击的 JavaScript 逻辑：  
```
window.addEventListener("message", function(e) {if (~e.origin.indexOf("https://hq.upserve.com")) {    if (e.data && typeof e.data == "object") {      try {        if (e.data["exec"]) {          eval(e.data["exec"]);        }      } catch (err) {        console.log(err);      }    } else {      console.log("Non-object passed");    }  } else {    console.log("Incorrect origin: " + e.origin.toString());    return;  }});
```  
  
问题暴露：if (~e.origin.indexOf(" https://hq.upserve.com"))  
 条件不够严格。它会接受任何包含https://hq.upserve.com  
 的域名，例如：  
  
https://hq.upserve.com.attacker.com  
  
这允许恶意网站向登录页面发送 postMessage，并欺骗它使用 eval()  
 执行任意 JavaScript。  
# PoC  
1. 攻击者在以下位置托管恶意 HTML 文件：  
  
https://hq.upserve.com.attacker.com/upserve_xss.html  
1. HTML 文件向登录页面发送一个包含恶意 JavaScript 的 crafted postMessage，其中 exec 字段包含恶意脚本  
  
1. 当受害者访问此页面并点击链接或执行操作时，Payload 被发送，登录页面使用 eval()  
执行任意 JavaScript  
  
1. 结果：在登录页面上可以运行 alert(1)  
或凭证窃取等恶意脚本  
  
# 如何寻找此类漏洞  
1. 搜索 postMessage 监听器，使用 grep、Burp Suite 或 DevTools 等工具搜索 JavaScript 文件，查找：  
  
window.addEventListener("message", ...)  
1. 检查来源验证逻辑，查找不正确的来源检查，例如：  
  
```
indexOf(…) >= 0includes(…)includes(…)不使用 ^的正则表达式
```  
  
这些可以通过攻击者控制的子域名绕过：  
  
https://trusted.com.evil.com  
1. 检查消息处理，如果处理程序直接使用：  
  
- eval()  
  
- document.write()  
  
- innerHTML  
  
- location.href  
  
测试注入可能性。  
1. 构建 Payload，从恶意域名（或本地主机）尝试：  
  
```
window.frames[0].postMessage({  exec: 'alert("XSS")'}, '*');
```  
  
调整消息结构以匹配处理程序期望的格式。  
1. 在敏感页面测试，目标登录页，仪表板和管理面板等页面，这些地方的XSS具有很高的影响力和更高的赏金潜力。  
  
希望你能有所收获～  
  
原文：https://medium.com/bugbountywriteup/2-500-bounty-dom-based-xss-via-postmessage-on-upserves-login-page-dc899778ed31  
  
- END -  
  
**加入星球，随时交流：**  
  
**********（会员统一定价）：128元/年（0.35元/天）******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～**  
  
