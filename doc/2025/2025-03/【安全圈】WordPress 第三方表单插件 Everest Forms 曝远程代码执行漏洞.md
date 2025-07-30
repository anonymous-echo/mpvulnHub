#  【安全圈】WordPress 第三方表单插件 Everest Forms 曝远程代码执行漏洞   
 安全圈   2025-03-04 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
漏洞  
  
#####   
  
据外媒 Wordfence 报道，安全人员 Arkadiusz Hydzik 向其报告一款名为 Everest Forms 的 WordPress 插件存在严重漏洞 CVE-2025-1128，黑客可利用漏洞将任意文件上传至 WordPress 网站，从而实现远程执行任意代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhMb7NWibsOia2SPicAWlhBJ25MHf12gXSNJb9iakgZZo0GibpfibGUWPjiaTmb73eFw84VSCDNMibia0l3ylg/640?wx_fmt=png&from=appmsg "")  
  
▲ Everest Forms 插件  
  
据悉，这款 Everest Forms 插件**主要为网站管理员提供创建表单、问卷、投票等功能**。目前 Wordfence 已将所有信息提交给 Everest Forms 开发者，目前相应插件已发布 3.0.9.5 版本补丁修复相应 Bug，而安全人员 Arkadiusz Hydzik 也获得了 4290 美元（IT 之家备注：当前约 31274 元人民币）的漏洞奖励。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhMb7NWibsOia2SPicAWlhBJ25QBeeibsl9aJYoAm5kylNBTF1tRXBrlooGsHJKOXns2pl0fN9GXaJPMQ/640?wx_fmt=png&from=appmsg "")  
  
参考报告获悉，这一 CVE-2025-1128 漏洞的 CVSS 风险评分高达 9.8 分（满分 10 分），3.0.9.5 前所有版本的 Everest Forms 均存在这一漏洞，**目前部署该插件的网站 " 多达 10 万家 "**  
。  
  
针对该漏洞产生的原因，Wordfence 漏洞研究员 Istv á n M á rton 指出，问题在于 EVF_Form_Fields_Upload 这个类缺乏对文件类型和路径的验证，导致 WordPress 网站不仅能上传任意文件，还可能被黑客随意读取或删除任何数据；若黑客针对 wp-config.php 下手，就有可能控制整个网站。  
  
由于 EVF_Form_Fields_Upload 中的方法 format ( ) 对文件类型或后缀名没有进行检查，黑客可直接将包含恶意 PHP 代码的 CSV 或 TXT 文本文件重命名为 PHP 文件并上传，而 WordPress 网站会自动将这些文件移动到任何人均可公开访问的上传目录，这样黑客便可在未经过身份验证的情况下上传恶意 PHP 代码，进而触发漏洞在服务器上远程执行任意代码。  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】美国追回 2021 年铀金融黑客攻击中被盗的 3100 万美元](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068238&idx=1&sn=f24cc0f9962f89f077b6f37fbbbb1e5f&scene=21#wechat_redirect)  
  
  
  
[【安全圈】虚假验证码网络钓鱼活动影响超过1150个组织](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068238&idx=2&sn=c807685df25b8dd97cf78362316b2fbc&scene=21#wechat_redirect)  
  
  
  
[【安全圈】黑客滥用 Google 和 PayPal 的基础设施窃取用户个人数据](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068238&idx=3&sn=fadc819d47b14f0f312ff3b09d675f9e&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
