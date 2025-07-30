#  华天动力OA登录绕过漏洞分析   
原创 Ambition  进击安全   2024-06-10 15:40  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
**0x00 前言**  
  
    今天看到一位师傅在公众号发了一个新的文章是关于华天动力OA的登录绕过漏洞，今天我也来分析一下。  
  
**0x01 漏洞分析**  
  
    涉及到的xml内容：  
```
    <servlet>
        <description>app entrance service</description>
        <display-name>HtEntranceService</display-name>
        <servlet-name>HtEntranceService</servlet-name>
        <servlet-class>com.oa8000.appservice.htentrance.HtEntranceService</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>HtEntranceService</servlet-name>
        <url-pattern>/HtEntranceService.do</url-pattern>
    </servlet-mapping>
```  
  
可以看到接口为HtEntranceService接口，跟入相关class文件，查看代码内容。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXQOMxEngqH7gGDIDicsxLEe0hU7KsGkH5nrWA4zIL4PAVRuRicfQwUbMdFs3t2TysFcb3eGq5lVtMA/640?wx_fmt=png&from=appmsg "")  
  
在其中的dopost方法当中接收一个用户传入的参数为code参数，并且给到了变量userShowId变量。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXQOMxEngqH7gGDIDicsxLEe9BOHAMzVqAAMrbqmTFAZdprE0usfBytrGDxkhdYRWCicAct6vChueLQ/640?wx_fmt=png&from=appmsg "")  
  
最终传递到了login方法当中，第一个参数书当中，跟入相关方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXQOMxEngqH7gGDIDicsxLEeW8q3U781U8X1fWo8Iqz1hz8EhQV9p0uFgUqEEj7clsRp0yOz7XHODA/640?wx_fmt=png&from=appmsg "")  
  
进行判断是否为空，不为空传递到了login方法，我们继续跟入方法查看代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXQOMxEngqH7gGDIDicsxLEeIAoST9FIibnwNgzdA4ibDnTichyDdIACcVanFzxG6hKUiaU7ESs17AS15A/640?wx_fmt=png&from=appmsg "")  
  
可以发现其实我们只要传入正确的值即可成功返回，我们继续查看相关的方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXQOMxEngqH7gGDIDicsxLEe8XibZUIKQnxyoMsPNpuoG1qDH1vRCQPE5BVanTR7rBQXVZoZvXfoEkg/640?wx_fmt=png&from=appmsg "")  
  
查看上述此方法，可以发现这个方法根据名称可以知道是创建token的意思  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXQOMxEngqH7gGDIDicsxLEeFoPo4Fiabq7NIuvVMp3etuWCjxtcncCqxZ1TeLh9EGutXibO566wGpBQ/640?wx_fmt=png&from=appmsg "")  
  
可以看到代码根据userShowId以及Useragent和ip来获取到token，跟入geitUserToken代码查看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXQOMxEngqH7gGDIDicsxLEejdGP6LfR2iae56Fvk5RdicCn2ZH8a11ZSc9QHT3J2LxFIkxTT8owCB2w/640?wx_fmt=png&from=appmsg "")  
  
可以看到使用相关base64编码进行生成。  
  
**0x02 漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXQOMxEngqH7gGDIDicsxLEeLKCoWeTwLFicXXyvj6kibxobxnYRQQEWcsf6WwquCHnPiaW2ZTMQzWVvg/640?wx_fmt=png&from=appmsg "")  
  
可以看到页面上返回了一串jwt字符但是意思目标并没有这个admin账户，对其JWT解密的时候发现无法解密，因此我们只需要传入正确存在的账户名即可进行拿到对应的jwt认证。  
  
这里不进行漏洞攻击师傅们可以自行研究。  
  
作者联系方式：  
专业承接渗透测试、红蓝对抗、代码审计、免杀、漏洞挖掘、应急响应等安全项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
