#  【漏洞复现】XXL-JOB-Admin 前台api未授权 hessian2反序列化   
孤独成诗  Sec探索者   2025-02-07 01:13  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkJrGicxw4mL5UYpL9RmBdKdft5iatHZicb4BrxO3ENyQOEVKKDeSwTG2Jw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "组 61 拷贝 2.png")  
  
点击下方名片，关注公众号，一起探索网络安全技术  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
      请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
**01**  
  
**漏洞描述**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
XXL-JOB 是一个分布式任务调度平台，其前后端之间通过 Hessian2 序列化协议传输数据，XXL-JOB 的   
/api  
 接口允许未授权访问，攻击者可以构造恶意的 Hessian2 序列化数据并发送到服务端，导致反序列化漏洞。该漏洞主要影响 XXL-JOB 的早期版本（<= 2.0.2）  
  
  
**02**  
  
**漏洞环境搭建**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
下载地址：  
  
https://github.com/xuxueli/xxl-job/archive/refs/tags/v2.0.0.zip  
 ，这里选择v2.0.0版本，解压并使用IDEA导入项目  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUiaqpZtJYHWmUUKo8gbTxYTATjjebI7VX5IicwBwO7NbdSibVAycspuEbA/640?wx_fmt=png&from=appmsg "")  
  
初始化数据库，数据库文件在 /doc/db/tables_xxl_job.sql，执行完脚本之后，就会新建一个 xxl_job的数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUNp6OYkD4lT8Q7E6bASUIgaypyV9eSS3nhgx79B0VAZh8VkuCiafCxFA/640?wx_fmt=png&from=appmsg "")  
  
修改管理端配置文件   
  
xxl-job-2.0.0/xxl-job-admin/src/main/resources/application.properties  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxURiaghnfYb1sXU2icbOMhdPjKYiczxqfjM0iczgmdib0Ds3k4YSxypk806yw/640?wx_fmt=png&from=appmsg "")  
  
如果修改了管理端默认端口8080，同时也得修改执行端中的对应地址端口，/xxl-job-2.0.1/xxl-job-executor-samples/xxl-job-executor-sample-springboot/src/main/resources/application.properties  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUf4VhlGGptIYSuic9GGibhia1Z5ePfNcUewaFogiasstUuBzwFibsvmhckzQ/640?wx_fmt=png&from=appmsg "")  
  
启动管理端和执行端，两个都需要启动  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUhY0UD3A3P6g9r2xazLF9Dh98RibL4Frab6Kw0PZgicalJqDQ9KcTG2xg/640?wx_fmt=png&from=appmsg "")  
  
然后访问：  
http://localhost:8080/xxl-job-admin  
，使用默认密码（admin，123456）即可登陆  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxU7a6VU2MnepPkSFc7OdgMmqbCUwyhV79F50F6Xd7fVEL8xRO0RA8qNQ/640?wx_fmt=png&from=appmsg "")  
  
**03**  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
访问 http://127.0.0.1:8080/xxl-job-admin/api 时，可发现这是一个未授权访问，先全局搜索/api关键词，可以定位到是在JobApiController中管理/api这个路由  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUTxBvOMndh1hdcHLYdYcRiay8eluia6ubOelQicrSPG2WDcK2xiav2JFSaw/640?wx_fmt=png&from=appmsg "")  
  
进入com.xxl.job.admin.controller.JobApiController，发现这里默认关闭了权限控制，导致api可以未授权访问，这里就是/api路由的入口点，这里传入请求对象request  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUNefkbJLvSVIuqSb3o7hPCTvUySgPShQJ3ktPUyrmpXvwMkPyL00iaWA/640?wx_fmt=png&from=appmsg "")  
  
跟进invokeAdminService方法，来到com.xxl.job.admin.core.schedule.XxlJobDynamicScheduler#invokeAdminService  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUXibU4BAV1PdLLbKibel8SF17iafics0no5JAMSkfpef71ibKib1NiajTRzCqw/640?wx_fmt=png&from=appmsg "")  
  
继续跟进handle，来到com.xxl.rpc.remoting.net.impl.jetty.server.JettyServerHandler#handle，这里会将传入的request交给parseRequest进行处理  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxU94K3XovUB19svFruKfiaicWLI3w77TiavcloVrJ0NqibcIHoEUlpC2IrrA/640?wx_fmt=png&from=appmsg "")  
  
继续跟进parseRequest，来到com.xxl.rpc.remoting.net.impl.jetty.server.JettyServerHandler#parseRequest，首先从request中读取请求体，将其转换为字节数组，然后判断字节数组是否为空，如果为空则抛出异常；如果不为空，则进行反序列化  
```
private XxlRpcRequest parseRequest(HttpServletRequest request) throws IOException {
    // 从HttpServletRequest中读取请求体内容，将其转换为字节数组
    byte[] requestBytes = readBytes(request);

    // 检查读取到的字节数组是否为空
    if (requestBytes != null && requestBytes.length != 0) {
        // 使用xxlRpcProviderFactory获取序列化器
        // 调用序列化器的deserialize方法，将字节数组反序列化为XxlRpcRequest对象
        // 这里的反序列化过程是将字节数据转换为Java对象，通常使用JSON或其他序列化格式
        XxlRpcRequest rpcXxlRpcRequest = (XxlRpcRequest)this.xxlRpcProviderFactory.getSerializer().deserialize(requestBytes, XxlRpcRequest.class);

        // 返回解析后的XxlRpcRequest对象
        return rpcXxlRpcRequest;
    } else {
        // 如果请求体为空（字节数组为空或长度为0），抛出自定义异常XxlRpcException
        // 提示请求数据为空，无法进行后续处理
        throw new XxlRpcException("XxlRpcRequest byte[] is null");
    }
}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUtXs7gv0Uu8VibGjLhibHZJSgwAbTmcFMcxudJZ5sPP1cKuKVMoMjR38A/640?wx_fmt=png&from=appmsg "")  
  
在反序列化处下断点并开启dubug调试，使用burpsuite构造一个请求体不为空的post请求进行发送，IDEA可以成功拦截到数据流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUxGwzKvhwKfV9Vk8J8zJeIz8xj5ZA34mvPmx7GWxP8xkO5WpNTStQ9Q/640?wx_fmt=png&from=appmsg "")  
  
断点步入deserialize方法，来到com.xxl.rpc.serialize.impl.HessianSerializer#deserialize，发现调用了Hessian2Input的readObject方法，所以确定后端是使用 Hessian 2 协议将字节数组反序列化为指定类型的对象  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUiazZXlEBv2YgT5SA3dlBwUoMj8K9icvIXicyEdpw2mSmU2BSXwKEqydzQ/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**漏洞复现与利用**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
现在已经分析出来了xxl-job会将/api请求的请求体进行hessian2反序列化处理，那么复现就很简单了，可以直接使用各种带有hessian2利用链的工具生成payload进行发送即可。这里使用代码去实现，首先得了解hessian2，下面代码实现了hessian2的序列化和反序列化，会序列化生成一个hessian.ser文件  
```
```  
  
将生成的文件发送到目标即可完成利用  
```
curl -XPOST --data-binary @hessian.ser http://127.0.0.1:8080/xxl-job-admin/api -H "Content-Type:x-application/hessian"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUf0OP9DIQTr4dkVSo7KSuF9I99mvcTY7VrvVvcvUp3hX23GfFg4IcHg/640?wx_fmt=png&from=appmsg "")  
  
  
**05**  
  
**工具自动化实现**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
当然以上的代码已经可以实现了漏洞利用，下面对其进行工具封装，已经实现了内存马注入，命令执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUQx5ZStZLyibtEAWHjJSpb51kMTMictic9f3ia1PnElGiaiax0bebedffEhIQ/640?wx_fmt=png&from=appmsg "")  
  
命令执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxUCRjmvqsibfkpmdxC0iaSyDjbEGXqRL0k7ruHK2AJwFT5AQFPaJGUyVTw/640?wx_fmt=png&from=appmsg "")  
  
内存马注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nu5RSfRGpzPSut8l8KpynZwc8w3dtsxU6qzmIguu2oA8iaJfaWDNoqI0tnb0ntgR4nfovRosvo8A487F8uBKOnw/640?wx_fmt=png&from=appmsg "")  
  
**06**  
  
**漏洞修复**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOJECe5vg2C5YWgpyo1D5bCkEPVCSE8TicyQLuettC2pcGgfe3PY8L2lHia8ZWLcNr1Fz7p3pb69Voow/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
1、升级到 XXL-JOB 的最新版本  
  
2、  
对/api接口进行严格的权限验证，确保只有授权用户可以访问  
  
3、如果业务允许，可以禁用 Hessian2 序列化协议，改用其他更安全的序列化方式  
  
  
参考链接：包括但不局限于下面链接，当文章涉及侵权问题时，请与我联系，我将立即删除。  
  
https://xz.aliyun.com/news/10539  
  
https://blog.csdn.net/m0_63828240/article/details/141326602  
  
https://blog.csdn.net/LiangYueSec/article/details/142753382  
  
https://forum.butian.net/share/2592  
  
https://blog.wanghw.cn/security/hessian-deserialization-jdk-rce-gadget.html  
  
[https://mp.weixin.qq.com/s/AKufROJaT6DLDqyykslrAg](https://mp.weixin.qq.com/s?__biz=MzUyOTkwNTQ5Mg==&mid=2247489062&idx=1&sn=05deb2b83d036edcced217663e8e060e&scene=21#wechat_redirect)  
  
  
https://blog.csdn.net/Err0r233/article/details/140818646  
  
[https://mp.weixin.qq.com/s/w7EMFPAlwRAv0bwCoT5cIA](https://mp.weixin.qq.com/s?__biz=MzU3OTMxNjkzMQ==&mid=2247483902&idx=1&sn=86a1d59491f52324981e7e88029eca7d&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Melo944GVOIOyOhEZkrWlcianYlTNGEkfxOuWBhteCiaRdaHtePHhJMovro0Xia8kibfibrTD6TZPkMibu0pzvicIzHLg/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
          
  
  
