> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MDY1MDU4MQ==&mid=2247583238&idx=2&sn=353765459c0cc7e6976ff211a8b1eab9

#  超过46000个Grafana实例暴露于账户接管漏洞  
胡金鱼  嘶吼专业版   2025-06-24 06:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
超过46000个暴露在互联网上的Grafana实例未打补丁，面临客户端开放重定向漏洞的威胁，该漏洞允许执行恶意插件并进行账户接管。  
  
该漏洞被追踪为CVE-2025-4123，并影响用于监控和可视化基础设施和应用程序指标的多个版本的开源平台。这个漏洞是由漏洞赏金猎人Alvaro Balada发现的，并在Grafana Labs5月21日发布的安全更新中得到了解决。  
  
然而，据应用安全公司OX security的研究人员称，截至撰写本文时，超过三分之一的公共互联网上可访问的Grafana实例尚未打补丁，他们将该漏洞称为“Grafana Ghost”。  
  
分析师表示，他们的工作重点是展示将Balada的发现武器化的能力。在确定易受攻击的版本后，他们通过将数据与平台在整个生态系统中的分布相关联来评估风险。  
  
他们发现128864个实例在线暴露，其中46506个实例仍在运行可被利用的易受攻击版本。这相当于约36%的百分比。  
  
OX Security对CVE-2025-4123的深入分析发现，通过一系列利用步骤，结合客户端路径遍历和开放重定向机制，攻击者可以引诱受害者点击url，从而从威胁行为者控制的网站加载恶意Grafana插件。  
  
研究人员说，恶意链接可以用来在用户的浏览器中执行任意JavaScript。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ics9PefZyyiawUTXUNVakJSjYbic6wum1YJqR5It9vWbCssfFoIarUYKUuSc5ibtnibbOJic4tiaJIouzKQ/640?wx_fmt=png&from=appmsg "")  
  
开发过程  
  
该漏洞不需要提升权限，即使启用了匿名访问也可以发挥作用。该漏洞允许攻击者劫持用户会话，更改帐户凭证，并且，在安装了Grafana Image Renderer插件的情况下，执行服务器端请求伪造（SSRF）来读取内部资源。  
  
虽然Grafana默认的内容安全策略（CSP）提供了一些保护，但由于客户端执行的限制，它不能防止利用。  
  
OX Security的漏洞证明了CVE-2025-4123可以在客户端被利用，并且可以通过原生到Grafana的JavaScript路由逻辑来绕过现代浏览器规范化机制。  
  
这使得攻击者可以利用URL处理不一致来提供恶意插件，从而修改用户的电子邮件地址，从而通过重置密码来劫持帐户。  
  
尽管CVE-2025-4123有几个攻击要求，比如用户交互，受害者点击链接时的活跃用户会话，以及启用插件功能（默认启用），但大量暴露的实例和缺乏身份验证的需要创造了一个重要的攻击面。  
  
为了降低被利用的风险，建议Grafana管理员升级到10.4.18+security-01、11.2.9+security-01、11.3.6+security-01、11.4.4+security-01、11.5.4+security-01、11.6.1+security-01和12.0.0+security-01版本。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/over-46-000-grafana-instances-exposed-to-account-takeover-bug/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ics9PefZyyiawUTXUNVakJSjxUwhzZ5xNia981sovBvN0ahCeb7N6WpWt8mPmMHJBOmj4GZdE1X1orw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ics9PefZyyiawUTXUNVakJSjaMmqVUq91bPyFUuGRKjPLE86q47v1wFXc7Sqy4KpGjKUibQW7hdQkkw/640?wx_fmt=png&from=appmsg "")  
  
  
