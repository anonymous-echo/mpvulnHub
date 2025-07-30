> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMDY3MzQyNQ==&mid=2247484962&idx=1&sn=28dd1e741720ee5eac7a5fe978b1c1e4

#  SRC实战篇-webpack+弱口令库库出高危  
原创 lvwv1  OneTS安全团队   2025-06-23 07:00  
  
**声明**  
  
  
  
  
  
  
  
  
本文属于OneTS安全团队成员lvwv1  
的原创文章，转载请声明出处！本文章仅用于学习交流使用，因利用此文信息而造成的任何直接或间接的后果及损失，均由使用者本人负责，OneTS安全团队及文章作者不为此承担任何责任。  
  
  
  
  
**1.一个内网应用，正常使用burp抓包**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/kJjVGsbcK2CZMBia2SnbdecMcaQTkHrFQIzHRkrTN2O9d5xZtmSAGomzanEqwjaGRcMpicJV7ZLIC3KFjtBZkCVw/640?wx_fmt=gif "")  
  

```
http://IP:30443/static/js/app.816ab935a377690fb416.js.map
http://IP:30443/static/js/vendor.df683607e46711c5aae5.js.map 
http://IP:30443/static/js/manifest.8871ee49554244789dfa.js.map 
http://IP:31363/static/js/app.816ab935a377690fb416.js.map 
http://IP:31363/static/js/vendor.df683607e46711c5aae5.js.map 
http://IP:31363/static/js/manifest.8871ee49554244789dfa.js.map 
```

  
使用reverse-sourcemap还原app.js.map文件，命令如下:  
  
  
reverse-sourcemap -v app155.js.map -o output1  
  
  
**2. 查看还原后的源码文件**  
  
****  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2CZMBia2SnbdecMcaQTkHrFQRoG90M74njk9Jps9cA1rv06ZPGCnkuNVibLcNZ8OSFZW92Vial5Lxib1Q/640?wx_fmt=png "")  
  
****  
这个文件下载需要SESSIONID,继续寻找高危敏感接口  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/kJjVGsbcK2CZMBia2SnbdecMcaQTkHrFQIZEIaT95y6ibMOah4PFapu802kOicxVn02v0xsrI3zUSLL0cialmm6ia9A/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2CZMBia2SnbdecMcaQTkHrFQ6BFO42Aav1v3viceTxlyXnWSPACqQhthLrL3Ik5PodGzK6zvHkreqZg/640?wx_fmt=png "")  
  
  
接口很多，不一一看了  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/kJjVGsbcK2CZMBia2SnbdecMcaQTkHrFQNKVr8aDr7sQGkOQtAPOplhCUGTggEia40924dgGw6SfbXepGicren45A/640?wx_fmt=gif "")  
  
  
寻找敏感信息硬编码。。。。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2CZMBia2SnbdecMcaQTkHrFQ7aYG2z0XltrWZbXYvv0I3RYhr4FhibDOTrK6kSROdyzYMVcj4kCEUhA/640?wx_fmt=png "")  
  
  
多个关键词尝试后，无果  
  
  
**3. 尝试一波密码喷洒**  
  
****  
使用常见姓名+数字，喷洒密码获取弱口令进后台。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/kJjVGsbcK2CZMBia2SnbdecMcaQTkHrFQLhKphw9BaoZrrTT16bu8smo5icj5rKSviaInpH7SJYp7liaVLHk4gnibvw/640?wx_fmt=gif "")  
  
  
进入后台后使用解包的路径继续水洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2CZMBia2SnbdecMcaQTkHrFQHA18J2zCxGSz90Lb6hGjMucs6tIUZME8ZtLlKf5ZhaByj0yWreqO7g/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/kJjVGsbcK2CZMBia2SnbdecMcaQTkHrFQvnoqun1bdWsqKkricFkNlDXRPiboZR0mKB8rkibWMuIPia0E1PwiciaPgc4w/640?wx_fmt=gif "")  
  
  
此处省略了大量弱口令账号。。。  
  
  
**4.  文件下载漏洞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2CZMBia2SnbdecMcaQTkHrFQbibalDibgtCaMcW87nxLWaz3sSiaTia5tMaFHCVmI0aPqeWhKOqEgFkUGw/640?wx_fmt=png "")  
  
**5.  文件上传**  
  
****  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/kJjVGsbcK2CZMBia2SnbdecMcaQTkHrFQ3K0byZ00RI2G2S90GJ3Zbic1GDv6Yq1zwQxYrSicEsYmvyibw5R1Rfxtw/640?wx_fmt=gif "")  
  
  
**高危拿下**  
  
