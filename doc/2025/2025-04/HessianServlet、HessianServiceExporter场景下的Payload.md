#  HessianServlet、HessianServiceExporter场景下的Payload   
原创 guchangan1  L0una   2025-04-23 11:28  
  
   
  
  
# HessianServlet、HessianServiceExporter场景下的Payload  
# 首发先知社区  
## Hession漏洞利用现状  
  
目前 Java 开发框架里使用 Hessian 去做面向对象的 RPC 传输，大部分都是使用 HessianServlet 以及 spring-web 组件里的 HessianServiceExporter  
 去暴露 hessian 服务，但是使用现有工具生成 payload 去打就报各种错，实际上 HessianServlet  
、HessianServiceExporter  
 在解析 Hessian 序列化数据时会进行一些协议头判断，而 web-chiasn 生成的都是针对自封装调用的 Hessian 直接打的，并没有针对 HessianServlet、HessianServiceExporter 场景做 payload 封装，导致无法攻击成功。  
  
  
报错如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXhakeJ5JEnCw5QGsvPvmJfKkt6bAXKlEKicib1vLBJYa5Yq6FdG1k6Rmg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXFvcMcy0s35JzlNUcwOgtQByqJK1CHO8pkxNlpABvVuJ2fzykVDAxQA/640?wx_fmt=png&from=appmsg "")  
  
## 组件代码分析  
### 访问特征  
  
针对 HessianServiceExporter  
发布的 Hessian 服务，一般都是这么写的  
```
<bean name="/HessianService"        class="org.springframework.remoting.caucho.HessianServiceExporter">        <property name="service" ref="HessianService" /></bean>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXZEzc5v0r0JB8Nlz6ZMt1FMbYpc84icCcY52tj8jR4VlZVMZgziaL7hsg/640?wx_fmt=png&from=appmsg "")  
  
访问特征如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXJtAiaEGOmHnVgzKy7hnV5GEGEozzSwaf3uhEr6v0O1RWhjkZbSFhXgA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXlJCPEr7vQtL8kbibff2UPiciaK6atd7dTTp2MQSFKRYwQRic6ypicib0nNZg/640?wx_fmt=png&from=appmsg "")  
  
针对 Servlet 暴漏的服务  
```
    <servlet>        <servlet-name>hessian</servlet-name>        <servlet-class>com.servletserver.ServletBasicService</servlet-class>    </servlet>    <servlet-mapping>        <servlet-name>hessian</servlet-name>        <url-pattern>/hessian</url-pattern>    </servlet-mapping>package com.servletserver;import com.caucho.hessian.server.HessianServlet;import java.util.HashMap;publicclassServletBasicServiceextendsHessianServletimplementsServletBasic {    @Override    public String SayHello(HashMap o) {        return"123"+ o.toString();    }}
```  
  
访问特征如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXqSdmFKkFyX97Ke0wRzPDBlG7gpx2juGUguia6ryicU2Une5bibpkgz7icQ/640?wx_fmt=png&from=appmsg "")  
  
  
### HessianServiceExporter 组件代码分析  
  
• POST 请求会进入到 invoke，对整个请求体(传入的序列化 payload)和响应体转发，跟进后赋值  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXymOvhDDuMmRNF1XyK8xL3pxpDMHz2Rt8UnD9DVuiaVEtiafo3UOhicGlw/640?wx_fmt=png&from=appmsg "")  
  
拿到输入流的第一位  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObX0Tib0CibwRjvDKYUfYCBb3SQeJr5qTSELb7VRH4TIbdQrc8dKYXsE1AA/640?wx_fmt=png&from=appmsg "")  
  
  
- • 首先进行第一位字符判断，是否是如下三种，H、C、c，若不是，直接产生第一种报错。  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXYThEyfh9AgWO1jzXc19zttY1nWeE0Ilwc4mRsdmJZt2d24bRH1xHnA/640?wx_fmt=png&from=appmsg "")  
  
  
• 倘若协议头为 H，还需要进行判断第二位是不是 0x02  
，也就是校验版本号是不是 Hessian2.0 是的话才会进行反序列化。这里因为正常生成的 payload 只是满足原生 Hessian 反序列化的要求，所以会报第二种错。  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObX48eQNMGybo0CDZDxq21FNZgzcgMjlPic9L6ZahYqF1AichuXhFrvdo1g/640?wx_fmt=png&from=appmsg "")  
  
  
进到 readCall 方法后，要满足第四位为 C (\x43)  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXmh8eNkow7iaDfNLIib9H2JDehrb4DxfGA2Gmn8kCULibPaIlmHQwHUjjg/640?wx_fmt=png&from=appmsg "")  
  
  
这样才能正常进入到 skeleton.invoke(in, out);  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXPP2XBZoBPPu7Xw2pBL9XzWNCmCgOPqGVyDiasQIU4gKYwiaktoVicuUdw/640?wx_fmt=png&from=appmsg "")  
  
  
然后后面就是正常的反序列化流程了，这里不再赘述反序列化流程，可以看下调用栈，有需要的自己查资料  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObX8LVbX9zfxQPFV0TqibRb1j5G1opao3UezNdG0LVTcf97EEhWCLZ8hOw/640?wx_fmt=png&from=appmsg "")  
  
  
所以可构造出\x48\x02\x00\x43 ，此时即可不报错，并且执行 payload  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXAC3O0fcFtrMOxEGpylmuLLb5mP31wvtBeDIiccEoUx5vsbODhqb9BRg/640?wx_fmt=png&from=appmsg "")  
  
• 倘若协议头为 C，通过 reset() 回滚流的位置，重新读取数据，也没啥特殊处理的  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXa8AicL3I8cCia5fQjR0bnUVJicb7eAr48YOuTwcfWlIQyPLvvuxzP5M7A/640?wx_fmt=png&from=appmsg "")  
  
  
就加个\x43 就行  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObX2XgSWFYpF9PCibLAdG3jMJWMUYce1oumECquNicM45IePudlvkjq7AvA/640?wx_fmt=png&from=appmsg "")  
  
• 倘若协议头为 c，创建 Hessian 1.0 输入流，如果主版本 ≥2，用 Hessian 2.0 输出,否则用 Hessian 1.0 输出  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObX7YG8tpQgQVGeG08AIKMdhH13GC6kqcgwxRmCaOoiaGmxVMZlzQKuC9g/640?wx_fmt=png&from=appmsg "")  
  
  
     那根据上文就可以构造出\x63\x02\x00，同时这里的 HessianInput 是用 1.0 的 payload 打，实际上这样是不能触发 payload 的，因为 HessianInput 的 readMethod 并不像 HessianInput2 一样里面可以调到 readObject  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXLc6JVT3MAkMJzpGIyK5zv1r6E3QNOwXHIvObzUBvUBaXleVKUAKF1Q/640?wx_fmt=png&from=appmsg "")  
  
  
所以反序列化点是在这里  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXLpAqqyt6qbDGxcSFwL5DtZeMQOIY4wibHicV0eCQtnjB118889cHhgfg/640?wx_fmt=png&from=appmsg "")  
  
  
但是目前 in.readHeader()  
获取到的是 null，导致无法反序列化，看下逻辑  
  
- ![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXXXZYdOXkAjbia7ibkPySbah8ZONu6FUMtwciaWGeEN221smRIQibOOsa3A/640?wx_fmt=png&from=appmsg "")  
  
          
  
这段代码的意思就是判断首位是否是 H，如果是再根据第二位和第三位指定要读取的长度，使用 parseChar 解析出指定的长度并返回，就看到三个 read()，第一位需要是 H，然后第二位给个\x00 赋 0 值即可，第三位随意，给个几，后面就跟几个字符串（感觉可以天然的加垃圾数据）那也就是在原先的基础上加一个\x48\x00\x03abc 这样就满足了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXCqH8IVXO8bOzo7fYLe3sB0KXKFRSwezynuhqskysTZTWUAcOAXFo1Q/640?wx_fmt=png&from=appmsg "")  
### HessianServlet 代码分析  
  
先到 HessianServlet 的 service  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXkwYcTRLXgwVV5NNaiciaCMEBTzKhNoQUcvZfnsG0JSsjCEZ98icjiaH0mw/640?wx_fmt=png&from=appmsg "")  
  
也是读取协议头，跟进看下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXGw0BsCxBgwYpRgkmfiaG8bWOdF6Ql3qwcPUn8ecib6f7tzkFL7zptL0w/640?wx_fmt=png&from=appmsg "")  
  
不一样的地方是这里直接读了三位，且由之前的 c、C、H 换成了 c、r、H ，C 没了，r 后续也用不上。所以就两种，c、H，c 和之前的一样也是根据第二位判断回复版本，H 就是 Hessian2.0，第三位为\x00 即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObXs7a1sn0c5c9WO83788IRkZBuLSZd7FRTWOrHoibQQrCL9s8wkACTRgw/640?wx_fmt=png&from=appmsg "")  
  
通用的，逻辑还是一样，Hessian2.0 依然会多读一位 \x43  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObX5aXKNib1dGE5toIV82Mz7vqHB66iagfL2sg8u6BgLyFrFwhYVibOmPmWA/640?wx_fmt=png&from=appmsg "")  
  
然后到了 invoke 就一模一样了，不再赘述。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MszXwh9LrScUWH3iam3D7eHBfRQ3WTObX7HEySd1wSLOFuMM4vyibZWG9ibXGHqWSVabQjff31qOqib9ZkSFBPfxWQ/640?wx_fmt=png&from=appmsg "")  
  
## 总结  
  
对于 chains 生成的 payload，针对的是入参点直接在 HessianInput()的情况，也就是自封装的比如 xxl-job 最后的调用点，如下代码，就没协议头的判断，就是正常的 Hessian 序列化流就行  
```
// 直接反序列化用户输入的字节流publicclassVulnerableService {    public Object deserialize(byte[] data)throws IOException {        ByteArrayInputStreambis=newByteArrayInputStream(data);        HessianInputinput=newHessianInput(bis);        return input.readObject(); // 关键漏洞点：直接反序列化为Object    }}
```  
  
而对于 Spring-web 包内，则是提供了 org.springframework.remoting.caucho.HessianServiceExporter  
 用来暴露远程调用的接口和实现类。  
  
对于 Servlet，则是提供了 com.caucho.hessian.server.HessianServlet  
用来暴露远程调用的接口和实现类。  
  
使用该类则需要添加协议头处理，对应的协议头总结如下。  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">协议头</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">ascii</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">hex</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">版本</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">输入流</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">输出流</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">备注</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 12.6px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">&#39;H&#39;</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">72</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">\x48\x02\x00\x43</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Hessian 2.0</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 12.6px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">Hessian2Input</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 12.6px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">Hessian2Output</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Hessian2.0 稳定利用</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 12.6px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">&#39;C&#39;</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">67</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">\x43</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Hessian 2.0</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 12.6px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">Hessian2Input</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 12.6px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">Hessian2Output</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">仅适用于 </span><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 12.6px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">HessianServiceExporter</span></code></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 12.6px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">&#39;c&#39;</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">99</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">\x63\x02\x00\x48\x00\x03abc</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Hessian 1.0</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 12.6px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">HessianInput</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 12.6px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">Hessian(2)Output</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">根据版本选择输出流。</span></section></td></tr></tbody></table>  
  
‍  
  
  
   
  
