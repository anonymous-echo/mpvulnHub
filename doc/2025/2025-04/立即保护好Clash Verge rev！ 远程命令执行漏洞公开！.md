#  立即保护好Clash Verge rev！ 远程命令执行漏洞公开！   
原创 一个不正经的黑客  一个不正经的黑客   2025-04-28 06:19  
  
# 立即保护好Clash Verge rev！ 远程命令执行漏洞公开！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoiak7Nib7XlHHr7kOFF621Nic6XXVJu2v2m1X1JibQVx8KAOcobjz0u4JLOD1ibz9lUqZmicl9VqJKDYsA/640?wx_fmt=png&from=appmsg "")  
# 免责声明: 本文仅限学习、研究使用！其他用途责任自负  
## 背景信息  
  
2天之前clash Verge rev 被爆出存在本地提权漏洞，群友们传的沸沸扬扬说这个漏洞本质是命令执行漏洞。  
  
因为自己也用到这个软件，所以今天顺便简单分析一下，最终在MacOS系统结合一些小条件完成此漏洞升级的远程命令执行利用！  
  
当然其他系统也可以的，但是我手头没有这种系统，据群友说其他系统更简单实现命令执行，这里不深究了，直接开始我们的小分享吧。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoiak7Nib7XlHHr7kOFF621Nicf3oNbiaVlGRuNicF3jC30sQ3WibkUibH2WcOl24aT4YowsIicJK9tGGOtwA/640?wx_fmt=png&from=appmsg "")  
## 漏洞成因  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoiak7Nib7XlHHr7kOFF621Nicic1HZTvB6lR1fU6IC3y6iax1IbQNzEWicytJu2DHXqlnNUpjDYxm6qQcg/640?wx_fmt=png&from=appmsg "")  
  
跟进  
  
https://github.com/clash-verge-rev/clash-verge-service  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoiak7Nib7XlHHr7kOFF621Nic8SvEY6ZGT874oa9XmqLeYpZzx64txaibjaAxzwicjtlEqKLFU3VP4EZQ/640?wx_fmt=png&from=appmsg "")  
  
懂得都懂，开发组已经连夜修了，核心出在service服务，本地会监听33211端口，支持通过HTTP RPC的方式传递binpath参数进行命令调用。  
  
具体成因大家可以自己去看看代码，我后续有空的话也会去跟进看看，看看能不能挖掘出更加有趣的东西!  
## MacOS RCE  
  
漏洞端点: http://127.0.0.1:33211/start_clash  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoiak7Nib7XlHHr7kOFF621NiccUtVZ2az2RAvtZCWd5k5xdjoe8GwRyImM83RicEk8ssNIw5Cjgb94qQ/640?wx_fmt=png&from=appmsg "")  
  
执行的命令序列如下，默认是用root权限执行的，所以这里是一个可以导致权限提升的地方。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoiak7Nib7XlHHr7kOFF621NicaVjvYCqq20lBz5a0QX6OvE4vJTmLL1hjAl5wa4l6utvV1RkcYSEOzA/640?wx_fmt=png&from=appmsg "")  
  
一开始我尝试，直接拼接参数如 ; || 在其他参数那里,发现并不是很行，问了下AI似乎也说args没办法绕过，没时间深究了哦。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoiak7Nib7XlHHr7kOFF621NicARMAy5UGYgtVlcbc93CVf8lia8GicS0pqLEOKs4m35X2wk9WKK8KOoIw/640?wx_fmt=png&from=appmsg "")  
  
既然如此，只能发挥我的小脑袋了，有没有办法曲线救国，完成rce呢？   
  
确实是有的，下面给出的一个思路（可能还有很多种方式，并没有深入了）  
  
只需要发起两个请求即可:  
  
1.利用  
curl命令，通过  
curl命令我们可以指定的  
 -d 为任意参数，  
 -f 为我们指定的服务器，然后控制  
log_file参数为一个可执行的文件（任意写入，路径穿越之类的，很好找这类文件），之后  
root权限覆盖写入此文件内容，同时保留 +x 的权限。  
  
2.指定bin_path参数为第一步恶意覆盖的文件路径：rce.sh  
```
#!/bin/bashopen -a Calculator
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoiak7Nib7XlHHr7kOFF621Nic2Pc9toceQLMxgiadpSjN0vpUkgiam1NR70yGbVYMpGibpwCpaKLYbRWEA/640?wx_fmt=png&from=appmsg "")  
  
RCE 啦！！！  
  
那么这个点能不能远程命令执行呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMoiak7Nib7XlHHr7kOFF621NicUP0hvE9bmh7O1ibWzictmTmXFFxlNT2XpXvwicSC5m7SLhWXKUtXg87zQ/640?wx_fmt=png&from=appmsg "")  
  
如果你把这个局域网连接设置打开了，恭喜你哦！  
  
那么别人就可以通过代理，直接远程局域网控制你的电脑了啦  
  
这个点，我已经在另外一台电脑验证过的了，good luck to you！  
```
curl -x socks5://x.x.x.x:7890 http://127.0.0.1:33211/xxxx 
```  
## 后话  
  
本文并没有什么技术含量，只是很多人可能还没意识到这个漏洞的真正危害，所以做了点危害升级的利用说明。  
  
最后希望大家都能重视起来，及时关注官方更新，同时不要在不可信的局域网环境开放代理，也不要随意点别人的链接，特别是一些红队仔，且行且珍惜，别成为别人的肉鸡了！  
  
共勉。  
  
