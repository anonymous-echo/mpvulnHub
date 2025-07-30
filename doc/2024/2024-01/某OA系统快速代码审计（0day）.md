#  某OA系统快速代码审计（0day）   
 探幽安全   2024-01-14 23:45  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
**0x00 前言**  
  
      
再一次寻找源码的过程当中，从某网盘搜索到了一个某OA系统，对此进行了一个快速代码审计。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhUic2Ad0ufbG7DcRrETnHa9t7ScUTib7QeYRkkQicdJbicKGwo3m24DFokPibUiarhPcPWRUZez1LDZ3FibA/640?wx_fmt=png&from=appmsg "")  
  
  
**0x01 审计过程**  
  
还是一如既往，快速定位出鉴权函数或者脚本，但是这里因为是OA系统吗，有点过多的繁琐，所以这里自己编写一个脚本将其中地php文件全部都筛选出来。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVw9m4RS2S0uRlzZC9mvxzHQKTF5Ts3MlEicugY7uQ5M4Mcic0wCfAbAdTK0uU9evyQibib9ZNFvciadIQ/640?wx_fmt=png&from=appmsg "")  
  
1000多条，使用burp进行本地爆破一下。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVw9m4RS2S0uRlzZC9mvxzH5ic1uKdldw0UnGDmibRZzzj1K9Wtn7HIhZicVDoBlJAAZbZKVVYCzbqEA/640?wx_fmt=png&from=appmsg "")  
  
这里发现状态码全部都是200，但是其中回显地长度只要不是200多，那么就是一个未授权访问，根据这一个特征进行审计。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVw9m4RS2S0uRlzZC9mvxzH53vtRpSg97Y7YngAZeZT5atibF6EslahicAmOpvb5WE8XtWntBw1wskw/640?wx_fmt=png&from=appmsg "")  
  
成功地发现了一个前天RCE漏洞，稍后我们验证一下，在代码第51行还存在一个任意文件上传漏洞，其余地文件基本都是php当中嵌套了大量的HTLM代码，最多是一个XSS漏洞，先来验证上述漏洞吧。  
  
**0x02 漏洞验证**  
  
将路径拼接上去之后发现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVw9m4RS2S0uRlzZC9mvxzHYDZrnjRtnFI8RuATcH7UsZQja2esibcmutvzEJKzJzEYk6J7Xxl0ysQ/640?wx_fmt=png&from=appmsg "")  
  
这不是三个漏洞吗，我们现在审计出来了当前的一个任意文件读取，并且这个是未授权访问，  
但是在下方其实还有一个人任意文件下载漏洞，我们回到代码当中进行查看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVw9m4RS2S0uRlzZC9mvxzH9IGQ0wq0r8jxmm5MTO4mtf7NChCIFXdyYp4CAuqxoibgctbMBXrUd6Q/640?wx_fmt=png&from=appmsg "")  
  
原来在上方存在一个下载文件地功能。  
  
RCE验证。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVw9m4RS2S0uRlzZC9mvxzHeFsM5mIsjYBp7UaT8IVzHXGD0gYnCvKhWeYjwbhtiajNicibgKPpIm3iaA/640?wx_fmt=png&from=appmsg "")  
  
echo "<?php phpinfo();?>" >1.php  
  
点击创建，进行访问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVw9m4RS2S0uRlzZC9mvxzHUN7AxS0UTT1r9tUzNMyLn4XQHAicicCrd4nX4ppnxcMV6YtUBPrIbZzQ/640?wx_fmt=png&from=appmsg "")  
  
成功写入文件，然后验证文件上传漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVw9m4RS2S0uRlzZC9mvxzH1hHJAJ1m4evFl5RoG2Yd2VbIw2EPXpUgO1m4micUn3sCttO3RUpgT4g/640?wx_fmt=png&from=appmsg "")  
  
  
点击上传文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVw9m4RS2S0uRlzZC9mvxzHUx4KUA2coXLDC3iaRy75nRjXVeQhmYLI9Biaoz4GGoDf80k3JCPiapH8Q/640?wx_fmt=png&from=appmsg "")  
  
  
成功传到上述文件，接下来验证任意文件下载漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVw9m4RS2S0uRlzZC9mvxzH0kkj5icMeRugvraH5ibibIXfMZ9CrYJNGDuicREaXjNlYGLibukUL3G5OSQ/640?wx_fmt=png&from=appmsg "")  
  
这里用的是绝对路径进行下载的。  
  
**0x03 POC编写**  
  
    先去找网站的特征在fofa上进行搜索查看资产  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVw9m4RS2S0uRlzZC9mvxzH3IEfdRVjic4kALgFShFlo7dnBia3icqH1ncfpic0nIndcHb0vRYh0sq9PA/640?wx_fmt=png&from=appmsg "")  
  
小众OA并没有很多人使用，写一个脚本看看多少个网站存在漏洞吧。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhVw9m4RS2S0uRlzZC9mvxzHWQGdOuc0L7pqvTytQgaZLmAyPdTWLpQPWPpbjjZT0YuzWjcVjm9UUA/640?wx_fmt=png&from=appmsg "")  
  
经过测试共有62个网站存在相关漏洞，本次代码审计到此结束！！  
  
加我好友可以获取相关POC模板哦  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
  
