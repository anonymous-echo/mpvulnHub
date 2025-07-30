#  从API接口信息泄露到挖掘出一个RCE   
 哈拉少安全小队   2024-06-03 20:00  
  
## 信息收集系列（一）：从API接口信息泄露到挖掘出一个RCE    
  
前言：这篇文章最核心的一点就是信息收集  
  
信息收集非常重要！！！  
         
  
大家都很清楚我很喜欢从小程序入手  
  
这次也不例外  
  看我如何从小程序突破到RCE       
  
开局：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokHGJiclkEIUYdSZeibF1TrwN9d826lLiaaeYyjA9ibpZTzOzOu0DJ0GM0QA/640?wx_fmt=png&from=appmsg "")  
  
  
一个很普通的综合信息平台开局  
  大家挖洞应该也碰到了很多次  
  碰到这种一般来说没有账号很难办 登录不进去 巧妇难为无米之炊        
  
没有账号 在前台耗费了很多时间       
  
第一个测试点：小程序的url地址可以放到浏览器去访问一遍，看看web端是什么表现   
  
这个测试点可能很多人会遗忘掉 但是这确实也是一个很重要的测试点  
      
  
浏览器访问：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNoksu7OibuQXb7b7J3m2zTbibrGvsmrfXSlDvoDQ2eysickA74zjS7OvEuVw/640?wx_fmt=png "")  
  
  
显示404 一般来说这里是没有什么测试点的 但是也有不一般的时候  
  
这个时候思路：      
  
**查看js代码---->扫目录---->扫端口**  
  
这里我就不浪费时间了，扫到了一个端口：8010  
  
访问：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokTJdlN0fTIxnESOQ03GB7TM3EE05O2hs6eicNV9r5eznsQcHJ8LF2gzg/640?wx_fmt=png&from=appmsg "")  
  
  
             
  
OK  
  发现了这个综合信息平台的web端了 原来换了一个端口来映射web端  
  
继续查看js代码  
  
发现了他所有的接口都是在  
/jeecg-boot  
 目录下面的  
  
那么拼接一下这个根目录 再去bp里面去fuzz 一下API接口  
   
  
这里需要fuzz两个端口下面的接口一个 8010 一个9010 不要放过每一个可以信息收集的点 这个很重要      
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokwGccV0op0HqaqSwwGGJzKHaQHxfN2h0W7iahOGCL7Nf7ibrNplfpSA0Q/640?wx_fmt=png "")  
  
  
实际上也是这样 幸好两个端口下面的接口都fuzz 了 在web端 8010端口并没有发现什么有用的信息  
  
但是在9010端口就fuzz出一个API接口   
/jeecg-boot/v2/api-docs  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNok1ggf7l2dwNqdmhq4ONnaiaybTCgTvONuAne54NeMiao820I0lGpwNYDA/640?wx_fmt=png "")  
  
  
             
  
好 发现了一个经典的API接口泄露 里面泄露了各种信息 包括如何去构造数据包 如何获取人员信息 各种数据接口  
  
下面根据这些信息去构造      
         
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokXrf75YQsQj3EVIINibllKmt1pQPIDBYnAqI56icVibIjgw6GKqhzPmzNw/640?wx_fmt=png "")  
  
  
根据获取人员信息接口去构造一个数据包  
  这里提示Token失效 显然是需要一个Token的，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNok1IHlJwR4LiaoicjljTJPuicmoKoavicutVib6fk89LASlpnXfaoK5qvuKUQ/640?wx_fmt=png "")  
  
  
在一开始泄露的接口中发现了一个X-Access-Token 参数  
  
那么继续构造数据包      
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokH3ib56YMlx5uTlCBHppzpEtusa1HLqsq7UQacEqQHdTsrYxQhYvLj9Q/640?wx_fmt=png "")  
  
  
仍然需要token 但是现在我们没有得到cookie具体值  
  这怎么办呢？貌似又打不动了  
  
小技巧：改一下请求方式，可能会有意外的惊喜  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokcB030Zj1JjSV7AIiatVcpSzbKgyibibXrSicxX8icuRNI6jLTXEZ5LjrSRQ/640?wx_fmt=png "")  
  
  
改为POST提交  
  哎嘿 发现了好东西 好像是springboot经典报错！  
  
如果这样看起来不明显  
  我们这么看      
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNoka7mlvQrURjDUJQWXhMZ7kZRhvQiah2iaYEpgH4GwzgxWPQp9AmBprpiaQ/640?wx_fmt=png "")  
  
  
             
  
这应该很明显吧 springboot  
  
那么既然是springboot  
  那测试就很明朗了 看一下springboot经典路径  
  记得在前面加上**/jeecg-boot/**  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNok5Nia5jjkVkePaU5fib1ic0w2X1cjwX3RnTFMe3Mbibpcy9UOtHwjRXdbeQ/640?wx_fmt=png "")  
  
  
发现了四个路径  
  只有一个httptrace有用  
  
咱们去看看 因为这个路径会保存一些登录信息 运气好会有管理员登录信息      
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokkzX4j9gFYQlwyiaUiarTVMHHb7sUra3HwYx9YRGcYXv0yknFPRBB6hYw/640?wx_fmt=png&from=appmsg "")  
  
  
运气很好 拿下了一个一个登录cookie  
  
非常好  
   
  
继续回去构造数据包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokemdnF6ss0JjY39syal0rFEKrsDt9GiaR6vVB1RIRzojCg5wIwvbgPRA/640?wx_fmt=png&from=appmsg "")  
  
  
Ohhhhhh  
  构造成功！！！拿到了人员信息 既然一个构造成功 那么其他的也就好办了         
  
根据前面API接口的信息      
  
查看全平台用户信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokpBzBEOGh222bM7uoHmMknU6GSqav3kA0kyk8U6tjibw4icGvg7rSoVVA/640?wx_fmt=png&from=appmsg "")  
  
  
查看所有学生信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokCHbnNhxYOCktfHNd5Sbsg1zcZsKyvwpib43751laA0u2drpzJBuZwcA/640?wx_fmt=png&from=appmsg "")  
  
查看所以学生父母信息  
  
通过userid就可以查询 userid可以在第二个学生接口全部查到      
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNok52GbT1SnL3ibh0Mfroia0AFicCOhjYoJM0eBP5giceib7mfOm6YZN6upZ1g/640?wx_fmt=png&from=appmsg "")  
  
  
全平台信息都可以拿到  
  
现在我们回到第一个老师接口  
  泄露了老师的手机号  
  那么我们可不可以通过这些手机号尝试去登录系统？  
  
密码就使用弱口令 123456  
  
尝试接管账号      
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokcuh8asa2THyZlZmZbAyLEJFkvBkyiab5xpENIXgiarwbUokLvBugOuQQ/640?wx_fmt=png&from=appmsg "")  
  
      
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokLG4DjwTRWCxkQJRd6xHicWOaw0icoCEqvCTDB2TAIkvKThtI2N84LxMw/640?wx_fmt=png&from=appmsg "")  
  
  
接管了很多账号 这里就用两个当例子  
  
当然了 小程序都可以接管了 那么web的那个网站肯定也可以去接管了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokhfHV5KWp9HOwcu255RR0OOKRJ9Pibib4RqNNoPjP8WLWrxc5EoVciaZ7w/640?wx_fmt=png&from=appmsg "")  
  
  
这里就不放截图了 反正都是差不多  
             
  
进入后台 全数据泄露  
       
  
下面开始RCE  
  
因为在前面我们发现了jeecg-boot 和spring-boot  
  
猜测 jeecg-boot 和 spring-boot 是一类的框架  
  
去百度一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokp8qCorYgjlvLPonzThiajMk2CiaXMdV4O1Cc0QP9xibu29fg0o6nTZahQ/640?wx_fmt=png "")  
  
  
发现和我们猜测的大差不差  
  
发现是开源的 既然是开源的，那么就一定有人审 我们直接去找nday 找不到我们就就自己去审源码  
    
  
https://www.cnblogs.com/fuchangjiang/p/17676837.html  
  
https://xz.aliyun.com/t/13224?time__1311=mqmxnDBD9AqQq405DIYYK0%3DFYRxfr2OR0TD&alichlgref=https%3A%2F%2Fwww.baidu.com%2Flink%3Furl%3DVvIr9G-jQmSJdXpyA4r-ZRDccarNdNF6ju1m094z-E9QPuy-q1H5Do_PhMV-DWQT%26wd%3D%26eqid%3D9b8ec8180040483d000000066627c99b  
  
找到了两个nday       
    
  
我们直接尝试  
    
  
Sql注入：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNok6G7HQEhxdOsYxfuaCnJDYmP7GiaPUDMMMUCNC7JtSwdm2bGZdP1259A/640?wx_fmt=png "")  
  
  
  
RCE:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNokKTQIaEJaJYSibtra3OniaM4ayib1495oa70SZibuSoEK6NCgo5B5jLOTCQ/640?wx_fmt=png "")  
  
  
后面继续找相同资产 就是一个通杀了  
  
也是找到了七八个可以RCE的站点  
   
  
补充一下：  
  
后续找资产发现一个招标文件：      
  
![](https://mmbiz.qpic.cn/mmbiz_png/ra9gzRic2wgfF04mia8QnZhhfddRG3jNoksSRzEibicu2iclzktH3Hj6P1oW4vDMcokrtQGuWxsrcmcLJ2OZo3k4qTg/640?wx_fmt=png "")  
  
  
这里有一个联系方式  
  可以直接通过这个手机号使用弱口令登录系统。。。。。。。。  
      
  
我服了  
  早知道这么容易我前面还干集贸啊  
  
所以说 信息收集越全  
  越容易出洞！  
  就不用我那么繁琐了  
  
             
  
             
  
             
  
             
  
             
  
             
  
   
  
