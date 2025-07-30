> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247512866&idx=1&sn=8d8edf81004848b4d30c926fab33c8c6

#  一个Flutter框架的App渗透日记 | 进入内网  
nstkm  李白你好   2025-06-19 00:01  
  
**免责声明：**  
由于传播、利用本公众号李白你好所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号李白你好及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
客户安排了一个App的渗透测试，但是App抓不了包，于是展开一顿分析，最终进入内网………….  
  
文章作者：奇安信攻防社区（  
nstkm  
）  
  
文章来源：  
https://forum.butian.net/share/4405  
  
  
**1**  
►  
  
**测试过程**  
  
  
1.使用Clash，打开全局代理进行抓包测试，发现验证码未加载，此时疑惑是否检测代理软件。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXoBk0SjFgrGjcQiaibpHAb1fqynS7WW840akxMtWMv5wsKg40KBxSHs2Jg/640?wx_fmt=png&from=appmsg "")  
  
2.使用clash透明代理将防火墙转发流量进行抓包测试，竟然抓到了相关的数据包，但是此时还是没有成功通信。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXoIXwRqvRXZbziceQtAMrKhic1QWic75oNUDlv9chwYNdibUQSiawLdutHODQ/640?wx_fmt=png&from=appmsg "")  
  
3.这时还是非常纳闷为什么抓到了包还是无法访问，于是将数据包发送至repeater进行单独的服务器访问分析。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXoCP9BqBtJk9TMgHusQTRJ1PGuoibWUZVTVSgYf9uG708t3Ny53V4Wu4Q/640?wx_fmt=png&from=appmsg "")  
  
4.很显然，这个数据超乎我想象的简单，也就是说它不像是APP构造的包，更不像浏览器构造XHRrequest包，尤其这个user-agent特别具有标识，这时对useragent信息进行收集，因为最初猜测可能和证书相关，最终确认是flutter框架开发的App，特征都能吻合上，so库以及useragent等特征。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXoBShPUI06lpx5X4jwQaB5pKjBPZd1BdCmlLhUTHz5ske5zghdlb1xbg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXo1V4WXrpibtiaPHaZg2ic0sGbbrTLicwLerImibYplI7LtMTvpMu7prZ4TbQ/640?wx_fmt=png&from=appmsg "")  
  
5.请教大佬以及熟人是否做过相关分析。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXo2eYEmgvqK7aNWYWOtZ2u9NEmgPZBG7AcFBAt5nYSpNhXicnp4ER1WMQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXoaGFGoRD0n4Q6HsBggXjPcMabQ3FKNAXO9mcWV0F57N04ia3BbYUR7Yw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXoKv37AqvxZajq1ANTaX51X6bS9v623YuJ4YV7hLWHrJmffAtxMBy3zQ/640?wx_fmt=png&from=appmsg "")  
  
6.由于在我收集的信息里，大量的flutter证书bypass的文章，我下意识就认为ssl的问题，但是师傅说的又没错，这是一个http的包。于是震惊我中华的第二天早上，我发现这tm居然是个内网地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXosx3t3hMXIGtqmPxGOWiaymAljaTQ0x7VLib8oOmib4esLZ6T9MANkIteA/640?wx_fmt=png&from=appmsg "")  
  
7.于是我百思不得其解，初步我设想是App做成本地请求+SDK(ssl认证转发发送)，于是我又尝试一些常规方法，对App源码进行分析，但是这个App源码竟然全体进行混淆，虽然没有加壳，但是这个混淆却异常的牛逼(有无师傅知道源码混淆如何还原，求求)，我尝试了关键词搜索，例如okhttp分析，libssl.so分析，以及一些字符串，JSON数据包hook分析，竟然没有找到任何与这个Dart发出来的请求相关的信息。然后就只能将希望寄托于网上的flutter分析，希望足够简单能够支持我解决抓包问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXo5lFgznwH9INnsAoPc2weBzg1N75NNzgMEdUeec0tUQJVp8YtCoB0Ig/640?wx_fmt=png&from=appmsg "")  

```
文章参考链接: https://www.ctfiot.com/217117.html
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXoPzEbgOlZOybjicrOyyIeTSm9Yb7H0RlKCNGt6TThTQ4u0KiczNg6dP8A/640?wx_fmt=png&from=appmsg "")  
  
8.于是拿到了so的ssl bypasshook函数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXoKOG8Q9ibic56FNvZTgFHnTr6IdmzdWXqD0knknwy9EK9UoJibnnmVN0mg/640?wx_fmt=png&from=appmsg "")  
  
9.万幸互联网居然有对这个地址的分析，我以为十拿九稳了，将地址填充进代码测试。![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXo6ryTqL4k65MFv1Somp7al6OdpeVe07jjhPWUib6ia23bwocqMXiaGQEhA/640?wx_fmt=png&from=appmsg "")  
  
  
10.如图下代码，进行hook测试，发现依旧无法成功抓包。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXoicXxr66xZ6kUDVhzdYFTqkC0SqW714uLdjELnF2P7HyZM3OtqHHDNVg/640?wx_fmt=png&from=appmsg "")  
  
11.此时心态有点崩溃，但是重新振作了一下，在github找寻所有的libflutter.so分析，终于找到了一个可以用的项目，这个点赞量以及项目更新时间都非常符合我心意。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXod5mPsLx1b9nyvpKiaPMFSfKxJoplraz7FpgIJSBbwcg7lxssPfDdCjw/640?wx_fmt=png&from=appmsg "")  
  
12.使用该脚本我成功做到抓包自由，当然该脚本细节也非常牛逼，将SO文件内存解析然后拿到导出地址来进行操作，对逆向分析flutter框架特别感兴趣的师傅可以研究一下。  

```
https://github.com/hackcatml/frida-flutterproxy
```

  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXowkC084Sm17NQFWBqZ8diaXl6DLKlyFkPXkJe3XjghbmhNajzR7Dur5w/640?wx_fmt=png&from=appmsg "")  
  
13.但是这个发出来的包还是，无法访问，但是我自作聪明的是，我有这个prod-api的公网地址，于是我用mitm给他替换成公网地址，侥幸通过了通信问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXonh3RmT9gPVNSMGaxnACXW1xu3GOS1FkyJkBic5npSCMdRASPd5YAhzA/640?wx_fmt=png&from=appmsg "")  
  
14.我也拿到了验证码成功的登录进了系统，我以为我能狸猫换太子这样的安安静静的测试了，但是！这个App核心业务是内置了的h5应用，也就是说有一部分请求是走的webview。也就是说该hook脚本只能抓包soket的包，也是通过flutter.so发起请求的包。并不能抓到js发起请求的包。于是我又开始对webview的分析。这里直接放送代码。  

```
Java.perform(function () {
//实例化一个对象
var WebView = Java.use('android.webkit.WebView');
//重写WebView类的重载方法，因为setWebContentsDebuggingEnabled不是静态方法，所以需要一个对象来调用这个方法
WebView.$init.overload('android.content.Context').implementation = function (a) {
console.log(&#34;WebView.$init is called!1&#34;);
var retval = this.$init(a);
this.setWebContentsDebuggingEnabled(true);
return retval;
}
WebView.$init.overload('android.content.Context', 'android.util.AttributeSet').implementation = function (a, b) {
console.log(&#34;WebView.$init is called!2&#34;);
var retval = this.$init(a, b);
this.setWebContentsDebuggingEnabled(true);
return retval;
}
WebView.$init.overload('android.content.Context', 'android.util.AttributeSet', 'int').implementation = function (a, b, c) {
console.log(&#34;WebView.$init is called!3&#34;);
var retval = this.$init(a, b, c);
this.setWebContentsDebuggingEnabled(true);
return retval;
}
//始终设置为true,打开调试
WebView.setWebContentsDebuggingEnabled.implementation = function () {
this.setWebContentsDebuggingEnabled(true);
console.log(&#34;setWebContentsDebuggingEnabled is called!&#34;);
}
});
// frida -U -f package_name -l .\hook.js --no-pause
```

  
15.该代码可以打开CDP分析的入口，于是我用inspect打开看了一下请求网络，我发现通往其他应用的入口竟然也是内网地址。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXohca6lU9TAeCDh7sMsPQGOfTzn7cTe6jXCfESenM7So4ckmGtWUqobg/640?wx_fmt=png&from=appmsg "")  
  
16.这时候我突然就意识到不对劲了，各种信息告诉我事情并非我想象的那样，于是我总结了一下信息，各位师傅还记得第一张图吗？是否关注到这里面有一个SanforidClient，组件里面也有大量的深信服的SDK。不会吧，因为我是第一次碰见深信服sslvpn sdk的App，但是我自认为应该没有开发那么蠢，在App里内置了一个默认的用户吧。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXoT3IjwXgUEgza3ZxUX7HW343eUrcTY3aUBPeHia8XrVaMBbIrGrsodicA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXoChvE9ibyRtPI0s3TsPs1XH99DeQTPLIyYbg9yJPedDWIDJAWZnkhVhA/640?wx_fmt=png&from=appmsg "")  
  
17.带着深信服Sdk的核心特征去github搜索，我从源码中关注到了认证方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXosdUjXlUw2C6VeLjYPO6iccrclt2RMERkxuvJSMD9QDU72XLdKJ7epmQ/640?wx_fmt=png&from=appmsg "")  
  
18.于是我成功拿到了认证的用户名以及密码以及服务器地址，成功拨进vpn。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUAE6ybIh7WnE56GkiaykbdXozSW05CghBwGIwFFDjFtMuvlwE5BPXTMcibWFwmP6fT5JyUF8I3ELYRw/640?wx_fmt=png&from=appmsg "")  
  
19.总结，也就是说，为什么抓不到包，是因为内置了深信服的sdk去通信，将流量通过sokcet或者回环也好转发至burp，由于PC并不能访问内网地址所以导致抓到了包也无法访问接口，同时也学习到了flutter的常规特征。后续如果碰到类似深信服SDK的可以直接进行相关账户找寻........  
  
  
**2**  
►  
  
**网安资源社区**  
  
  
李白你好VIP社区-  
网络安全资源社区  
  
https://www.libaisec.com/  
  
代理访问效果更佳  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/XoIcX2HtlUDqeYpptK8oyb4LAmJCwMmP5DIMmicsvvnLb9VAv30dic9fE5kz0ib8IaIPy5AEO4kxVBibsWvNUF7gLA/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
