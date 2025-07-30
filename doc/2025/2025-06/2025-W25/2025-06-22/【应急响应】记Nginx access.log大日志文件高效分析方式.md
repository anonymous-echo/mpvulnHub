> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMTY1MTIzOA==&mid=2247484687&idx=1&sn=e5a13a05e957fc978059528f1d5b5241

#  【应急响应】记Nginx access.log大日志文件高效分析方式  
 剁椒Muyou鱼头   2025-06-22 02:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
**阅读须知**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
  
****  
**本公众号文章皆为网上公开的漏洞，仅供日常学习使用，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把**剁椒Muyou鱼头**  
“设为星标”，否则可能就看不到了啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD01hM2Bw8oTpcNCZl68Bj8T0aLpOHAMFCv9Qd6KeeQgTscOURdQUDbLw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4Z7hc6oGV6C6IwibzfQUM1oq1yUciadAKQ3Ap29o8GGnBU52wXgSSicBxQ/640?wx_fmt=gif "")  
  
  
****  
**2025/06/23 星期一**  
  
**晴·西风2级**  
  
  
//01 前言  
  
  
    最近处理一起应急响应碰到了超大的  
Nginx下access.log日志文件，拷贝拷了2个多小时，还需要进行分析。但是因为日志文件太大无法直接打开访问，随即对该日志文件进行分割，然后提取所需要的时间段日志进行分析。分割日志文件用了3个多小时很折磨人。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA0ozYt0g1366kv2gswZ3tKicMGHWKqEGiaeiaOGudDUbAVnzouK9LQWX7mDj3KJ1PWib9LPa0FLDp4dDg/640?wx_fmt=png&from=appmsg "")  
  
  
//02   
access.log日志文件  
  
  
      
access.log日志记录了客户端访问服务器的详细信息，包括客户端IP地址、请求时间、HTTP方法（如GET/POST）、请求路径、协议版本、HTTP状态码、响应数据大小、请求处理时间、来源页面（Referer）、用户代理（User-Agent）以及可能的Cookie信息，若配置了反向代理或SSL还会记录后端服务地址和加密协议等，这些数据用于流量分析、性能优化、异常监控和安全审计。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA0ozYt0g1366kv2gswZ3tKica3H2rcFbbI3111YhDr9VnNLaVtlKF7qShHia5kWgUicLW4q0d2V5xfVQ/640?wx_fmt=png&from=appmsg "")  
  
  
//03 S  
plite分割日志  
  
  
      
Split是一个高效的Linux/Unix命令行工具，专门用于将大文件按指定大小或行数分割成多个小文件，支持自定义输出文件名前缀和数字后缀，常用于快速处理超大型日志文件以提升分析效率，是运维人员手动管理日志的实用利器。我是在windows下进行处理的所以需要先安装  
git，在里面使用  
Split工具。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA0ozYt0g1366kv2gswZ3tKicaMEmVYmIaxCD9dbXE4EbthfXnXJUfr8TJbG8mBsZPJuySfCib5we2JQ/640?wx_fmt=png&from=appmsg "")  
  
  
    安装完毕后，使用Split工具进行按需分割，我这里是分割了3次，分别分割为100G、20G、2G的文件进行定位我需要获取的时间范围的日志。这里可以搭配LogViewer工具秒开日志文件浏览确认自己需要的时间范围日志在分割好的哪一块。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA0ozYt0g1366kv2gswZ3tKicZSnLhibVqSoibD06PPTwppGezetvFxfJqz7M1K7e4YlHoe3w6GYfku6g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA0ozYt0g1366kv2gswZ3tKicibQjDPLDQXWa5BZFu087TibibyglxibBbO4AThN1n8ojY0Ggia1IwUbQDSQ/640?wx_fmt=png&from=appmsg "")  
  
  
    成功定位到需要的时间范围的日志文件，我这里目标比较明确，就是需要筛选20.171.*.*的一个IP地址，所以直接使用findstr命令进行筛选最终结果了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA0ozYt0g1366kv2gswZ3tKic44tkJpxo5UhKdavfUiaJIVCyEWAQPUPYQzkB3unkQqTfjdzibHrEicVTQ/640?wx_fmt=png&from=appmsg "")  
  
  
//04 结尾  
  
  
    没有什么技术含量的操作，我也是第一次碰到500多G的日志文件，看得头大。使用  
Split工具+  
LogViewer工具搭配进行处理用了大约3个小时的时间，主要是分割文件处理时间太长了。也许有人觉得可以直接在liunx下使用命令打印出来就可以了，但是实际上500多G的文件一运行需要卡死好长时间，在一个就是窗口打印浏览上限，粘贴板也有上限，超几十万次的访问记录没有办法完全保存下来的。  
  
  
  
    
END   
  
  
   
作者 | 剁椒Muyou鱼头  
   
  
I like you,but just like you.  
  
我喜欢你，仅仅如此，喜欢而已~  
  
  
  
  
**********点赞在看不迷路哦！**  
  
  
