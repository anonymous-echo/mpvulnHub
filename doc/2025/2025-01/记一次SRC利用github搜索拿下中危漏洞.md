#  记一次SRC利用github搜索拿下中危漏洞   
原创 zkaq-asdad  掌控安全EDU   2025-01-29 04:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  asdad 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
由于是某项目所以厚码，打开官网基本都是静态页面，没有什么交互功能，找了半天只有一个投诉功能，在投诉功能里存在附件处上，直接上传pdf型xss，点击提交后会返回查询码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLxo6fE0YJ89KOiaRneumgGlBcXZCpCIicYGMN7hOn0YSXrmYAVMMkHItTKA2j06ib6OicwqoLAHGXjg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
但是上传了没办法证明是否存在xss漏洞，在查看举报结果处查看举报结果，抓取返回包，发现返回了存储地址，一般来说这个时候直接路径拼接上url访问就行了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLxo6fE0YJ89KOiaRneumgGLWtcGBOqA6CBJ7emQNibXj7bWVeribAfiaf1jUhfD7BNXtrESEz4C1tqA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
进行url拼接，https://xxxx.xxx.com/+xxx.pdf 发现页面不存在，所以猜测存储上传文件的应该其他域名，比如img，Pictures开头的这类的域名。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLxo6fE0YJ89KOiaRneumgGYmHjqm2vsdYJu55UgmyjwVvwRzLYt6XGlkpDGv87bYY2SDangrIOFQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
有师傅可能不知道github信息收集的语法规则，在这里刚好给大家把部分常用语法放在下面了。  
  
•site:Github.com password  
•site:Github.com ftp ftppassword  
•site:Github.com 密码  
•site:Github.com 内部  
•in:name test # 仓库标题搜索含有关键字test  
•in:descripton test # 仓库描述搜索含有关键字  
•in:readme test # Readme文件搜素含有关键字  
•stars:>3000 test # stars数量大于3000的搜索关键字  
•stars:1000..3000 test # stars数量大于1000小于3000的搜索关键字  
•forks:>1000 test # forks数量大于1000的搜索关键字  
•forks:1000..3000 test # forks数量大于1000小于3000的搜索关键字  
•size:>=5000 test # 指定仓库大于5000k(5M)的搜索关键字  
•pushed:>2019-02-12 test # 发布时间大于2019-02-12的搜索关键字  
•created:>2019-02-12 test # 创建时间大于2019-02-12的搜索关键字  
•user:test # 用户名搜素  
•license:apache-2.0 test # 明确仓库的 LICENSE 搜索关键字  
•language:java test # 在java语言的代码中搜索关键字  
•user:test in:name test # 组合搜索,用户名test的标题含有test的  
  
接下来使用关键词目标主域名xxx.com搜索，在github搜索结果的第二页发现一个目标以img开头的域名,感觉有了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLxo6fE0YJ89KOiaRneumgG7pYxRCw3aEbrf50scMK3gb1vlP7Ex6d19ZicffBFkAxiaIwtxmXKUxWw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
5.尝试拼接https://img.xxx.com/+x.pdf 最终访问pdf地址成功执行xss代码，弹窗2,白捡一个洞，这个要看有没有说明不收pdf型xss，收的话就是一个中危500到手。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpLxo6fE0YJ89KOiaRneumgGu5U8gDUAZBFV179ItLgicvhIjjDUHMxiaynBiaoHLKcKL8qJf7p04fB6w/640?wx_fmt=png&from=appmsg "null")  
  
img  
```
```  
  
