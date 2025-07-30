> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2ODYxMzY3OQ==&mid=2247519474&idx=1&sn=27e66a7c83cd189f0b28f274424d0779

#  从 Self XSS 到 RCE  
 Z2O安全攻防   2025-06-16 13:27  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table># 前言今天和大家分享一个国外白帽子在一个私有赏金项目上有趣发现的故事。  
# 发现  
  
通过 Subfinder白帽小哥发现一项服务只提供了一个注册表单和一个个人资料页面，此外，还可以注册参加不定期的特定调查。  
  
总的来说，该页面没有任何可供探索的其它功能（只有一小部分注册用户，因此导致赏金最终被降级处理）  
  
通过检查个人资料字段中的一些 XSS，发现名字容易受到存储型Self XSS 攻击，使用如下Paylaod：  
  

```
&#34;onfocus=&#34;alert(1)&#34; autofocus=&#34;
```

  
  
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
  

```
&#34;><iframe src=&#34;file:///etc/passwd&#34;></iframe>
```

  
  
没能成功，而且每次 iframe 都是空的，看来是因为没有设置 
```
--enable-local-file-access
```

  
 标志，所以阻止了对本地文件的访问。  
  
另外，尝试在本地主机上请求服务也没能成功，因为服务器每次都会崩溃，不得不等待服务器的重新启动。  
  
白帽小哥尝试获取有关渲染器运行环境的更多信息：  
  

```
&#34;onfocus=&#34;document.write(JSON.stringify(window.location));&#34;autofocus=&#34;
```

  
  
这会返回一个包含以下内容的 PDF 文档：  

```
{&#34;origin&#34;:&#34;file://&#34;,&#34;hash&#34;:&#34;&#34;,&#34;href&#34;:&#34;file:////tmp/wicked_pdf20250319-23102-
1jmrqgy.html&#34;,&#34;pathname&#34;:&#34;//tmp/wicked_pdf20250319-23102-
1jmrqgy.html&#34;,&#34;hostname&#34;:&#34;&#34;,&#34;protocol&#34;:&#34;file:&#34;,&#34;port&#34;:&#34;&#34;,&#34;host&#34;:&#34;&#34;,&#34;search&#34;:&#34;&#34;}

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
  

```
&#34;><?= Time.now ?>
```

  
  
结果非常令人兴奋！每次请求 PDF 时，都会打印当前服务器时间 🙈  
  
将 Self-XSS 变成了 RCE 只需要：  
  

```
&#34;><%=
```

  
uname -a
```
%>
```

  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkmghicAzQ4GrTe4sdWkrib8Rf3yGg06kDP6f2mJMfs4axCg2sFTFdXRicvtK1Ru6P4yY5QMrzILWjag/640?wx_fmt=png&from=appmsg "")  
  
服务器系统信息  
# 深入探索  
  
白帽小哥决定进一步挖掘以获得更多发现和更多影响：  
  

```
<%=
```

  
ls -lsa /home/
```
%>
```

  
  
通过浏览了一些目录，白帽小哥发现了很多有价值的东西，比如 git 仓库、配置文件以及托管在同一服务器上的其它项目的数据库转储。  
  
该公司没有将这些项目彼此隔离，从而使这些项目面临被入侵的严重风险。  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkmghicAzQ4GrTe4sdWkrib8Rqtd5ESiaMx2Cl7MEGzUUfjjUajY3zOlZlbqwfx2ehxelaL1ibFkVt6hA/640?wx_fmt=png&from=appmsg "")  
  
目录浏览  
  
![file](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkmghicAzQ4GrTe4sdWkrib8RwicQRmRXZSl59arSPnJyK5gplA5JbmaVeonO75TQFb7oic7TakbyBbTw/640?wx_fmt=png&from=appmsg "")  
  
各类敏感文件  
  
很快厂商在一天之内便做出了回应，同时为该漏洞提供了一笔赏金奖励。  
  
你学到了么？  
  
建立了一个  
src专项圈子  
，内容包含**src漏洞知识库**  
、**src挖掘技巧**  
、**src视频教程**  
等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  

```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```

  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg41LkR0ezBlmjJY4Lwgg8mr1A5efwqe0yGE9KTQwLPJTe9zyv3wgYnhA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOXg868PqXyjsACp9LhuEeyfB2kTZVOt5Pz48txg7ueRUvDdeefTNKdg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuYY8q8CZqffeicCspiaq3u0y7lQ2ia1ZLXbhqIbjvnBdsrlTFOJjSXbu8fmmliaLticl6P0iaXjbnxokM0g/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4Bd1oBmTkA5xlNwZM5fLghYeibMBttWrf57h8sU7xDyTe5udCNicuHo8w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYrUoo5XZpxN9Inq87ic71D6aUeMdaWrKXgYYia2On8nMA7bqWDySa8odAq1a0kkp3WFgf0Zp0Eut0A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4KKlic4yiafWTpLdejicQe3MllEQc24ypeI3anaK7IjJDVyq1WVQN2yKBA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOHgjJxnq1ibibJgVUx3LwCjZj62vygx8w6rxia1icmIWiax2YlP6S6LmlmlQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOApVm8H605qOibxia5DqPHfbWD6lmcweDjGv4DLl45waD068ugw2Iv2vg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOwldaSATYOh1WQpk1qz15rLxehOAn4aK7tdbSyNEuHDZpIISCtl6Q8w/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4jFsKRMMNDKbsAZhscCiagnyJScMVmFUqMtae5omlLRdu095mywWszjQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4uGJ2SA5BhZ3UyibZvVmcP3sozQEOfVr0jftWpC3YkpDiaAicS1ib3EgXHA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
