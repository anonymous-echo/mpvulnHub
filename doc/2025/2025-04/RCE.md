#  RCE   
 迪哥讲事   2025-04-12 21:01  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>#   
  
#   
  
****# 防走失：https://gugesay.com/archives/4132  
  
******不想错过任何消息？设置星标****↓ ↓ ↓**  
****  
#   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jlbXyV4tJfwXpicwdZ2gTB6XtwoqRvbaCy3UgU1Upgn094oibelRBGyMs5GgicFKNkW1f62QPCwGwKxA/640?wx_fmt=png&from=appmsg "")  
  
# 前言  
  
今天和大家分享一个国外白帽子在一个私有赏金项目上有趣发现的故事。  
# 发现  
  
通过 Subfinder白帽小哥发现一项服务只提供了一个注册表单和一个个人资料页面，此外，还可以注册参加不定期的特定调查。  
  
总的来说，该页面没有任何可供探索的其它功能（只有一小部分注册用户，因此导致赏金最终被降级处理）  
  
通过检查个人资料字段中的一些 XSS，发现名字容易受到存储型Self XSS 攻击，使用如下Paylaod：  
  
"onfocus="alert(1)" autofocus="  
  
那么一个Self XSS 危害并不大，能否升级该漏洞呢？  
  
白帽小哥决定先休息一下，换个其它子域再挖挖看。  
# 重拾信心  
  
几天后，白帽小哥决定来用 ffuf 进行一些基本的模糊测试：  
  
通过在 URL 末尾添加 .pdf 后，页面返回了大量响应。  
  
页面网址为 https://subdomain.redacted.com/.pdf ，令人惊讶的是，登录页面的内容以 PDF 文档的形式返回。  
  
测试其它路径显示出相同的行为，并且服务器将请求的页面作为 PDF 文档返回……  
# PDF 文档  
  
使用 FileAlayzer 分析 PDF 后发现，该文档由 wkhtmltopdf 创建：  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkmghicAzQ4GrTe4sdWkrib8RsxB9wScEOgLm0d34vA3jQ0j9j9ubAdt3NjkIENnNibBhHq5fzhX2DAQ/640?wx_fmt=png&from=appmsg "")  
  
PDF 文件分析  
  
还记得之前的存储型 Self XSS 吗？不妨尝试将其转换为服务器端 XSS，然后读取本地文件，这样就可以进一步升级该漏洞，说干就干！  
  
请求 https://subdomain.redacted.com/start/profile.pdf 以 PDF 格式呈现个人资料数据页面 — 成功😍  
  
Self XSS 漏洞已在 PDF 文档中呈现……🎉  
# 漏洞利用  
  
参考：https://medium.com/r3d-buck3t/xss-to-exfiltrate-data-from-pdfs-f5bbb35eaba7 文章中的一些技术手段，白帽小哥开始尝试以下方式读取本地文件：  
  
"><iframe src="file:///etc/passwd"></iframe>  
  
没能成功，而且每次 iframe 都是空的，看来是因为没有设置 --enable-local-file-access  
 标志，所以阻止了对本地文件的访问。  
  
另外，尝试在本地主机上请求服务也没能成功，因为服务器每次都会崩溃，不得不等待服务器的重新启动。  
  
白帽小哥尝试获取有关渲染器运行环境的更多信息：  
  
"onfocus="document.write(JSON.stringify(window.location));"autofocus="  
  
这会返回一个包含以下内容的 PDF 文档：  
```
{"origin":"file://","hash":"","href":"file:////tmp/wicked_pdf20250319-23102-1jmrqgy.html","pathname":"//tmp/wicked_pdf20250319-23102-1jmrqgy.html","hostname":"","protocol":"file:","port":"","host":"","search":""}
```  
  
临时文件名前缀 wicked_pdf 引起了白帽小哥的注意，经过快速搜索，白帽小哥找到了 Ruby on Rails 的 wkhtmltopdf 封装器的 github repo： https://github.com/mileszs/wicked_pdf  
  
通过阅读文档，发现了一个有趣的部分：  
  
https://github.com/mileszs/wicked_pdf?tab=readme-ov-file#wicked_pdf-helpers  
  
看起来好像可以在 html 模板文件中使用内联 ruby 代码来包含自定义函数。  
  
因此引出了关于如何处理内容的一些想法：  
- 页面渲染完成（我们的存储型 XSS 触发）  
  
- html 页面内容传递给 wicked_pdf，后者也在 html 文件中执行内联 ruby，然后调用 wkhtmltopdf  
  
- pdf 文档成功送达  
  
那么当 XSS 执行时，白帽小哥考虑尝试注入内联 ruby 标签是否会发生什么呢？  
  
"><?= Time.now ?>  
  
结果非常令人兴奋！每次请求 PDF 时，都会打印当前服务器时间 🙈  
  
将 Self-XSS 变成了 RCE 只需要：  
  
"><%=  
uname -a%>  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkmghicAzQ4GrTe4sdWkrib8Rf3yGg06kDP6f2mJMfs4axCg2sFTFdXRicvtK1Ru6P4yY5QMrzILWjag/640?wx_fmt=png&from=appmsg "")  
  
服务器系统信息  
# 深入探索  
  
白帽小哥决定进一步挖掘以获得更多发现和更多影响：  
  
<%=  
ls -lsa /home/%>  
  
通过浏览了一些目录，白帽小哥发现了很多有价值的东西，比如 git 仓库、配置文件以及托管在同一服务器上的其它项目的数据库转储。  
  
该公司没有将这些项目彼此隔离，从而使这些项目面临被入侵的严重风险。  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkmghicAzQ4GrTe4sdWkrib8Rqtd5ESiaMx2Cl7MEGzUUfjjUajY3zOlZlbqwfx2ehxelaL1ibFkVt6hA/640?wx_fmt=png&from=appmsg "")  
  
目录浏览  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkmghicAzQ4GrTe4sdWkrib8RwicQRmRXZSl59arSPnJyK5gplA5JbmaVeonO75TQFb7oic7TakbyBbTw/640?wx_fmt=png&from=appmsg "")  
  
各类敏感文件  
  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5EMr3X76qdKBrhIIkBlVVyuiaiasseFZ9LqtibyKFk7gXvgTU2C2yEwKLaaqfX0DL3eoH6gTcNLJvDQ/640?wx_fmt=png&from=appmsg "")  
  
往期回顾  
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[挖掘有回显ssrf的隐藏payload](https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496898&idx=1&sn=b6088e20a8b4fc9fbd887b900d8c5247&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[一个辅助测试ssrf的工具](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496380&idx=1&sn=78c0c4c67821f5ecbe4f3947b567eeec&chksm=e8a5f8dfdfd271c935aeb4444ea7e928c55cb4c823c51f1067f267699d71a1aad086cf203b99&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips‍](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
  
很快厂商在一天之内便做出了回应，同时为该漏洞提供了一笔赏金奖励。  
  
你学到了么？  
  
原文：https://handball10.medium.com/from-self-xss-to-rce-in-ruby-on-rails-1f9f2d33c1cb  
  
  
  
