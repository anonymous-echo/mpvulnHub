> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNTUwNjgxOQ==&mid=2247484400&idx=1&sn=e831c59dacc0e92729b437568f87437c

#  从一次waf绕过来学习.Net JavaScriptDeserialize反序列化漏洞  
原创 ekkoo  艾克sec   2025-07-21 13:44  
  
文章首发于阿里云先知社区:  
  
https://xz.aliyun.com/news/18435  
  
作者：ekkoo  
> “  
> 距离上次更新公众号已经4个月了，工作后分享欲越来越低了...  
  
### 前言  
  
笔者在某次攻防活动中遇到了CVE-2019-18935,但是由于采用waf，有针对该漏洞编写的规则拦截，最终通过从代码侧分析该漏洞从而编写exp来绕过waf成功rce，整个过程收获颇多，记录一下。  
### 正文  
#### 一、漏洞发现：  
  
通过源码确定使用了该组件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VskUJ6U9XNdFQRHOF6XE5aYbmlGo2wqJibHhsFHcl1VDxUPJXGTz7aRtA/640?wx_fmt=png&from=appmsg "")  
  
并且确认版本在漏洞版本内：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsBgSGTKAAfZibpapPUvHfJwRicckGCblGdctxZ1ibLnr45a8Bz0KibDiapbA/640?wx_fmt=png&from=appmsg "")  
#### 二、尝试利用（waf拦截）  
  
尝试访问漏洞路由  
  
构造exp（waf拦截）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsGyLfbUlHniaVGHxdZ0yxM2sSSpxOVwnoeTpFm1fawBE26bEqOE4lmnw/640?wx_fmt=png&from=appmsg "")  
  
尝试了脏数据 并发 畸形数据包等等方式均无效，这样只能从源码侧进行waf绕过  
#### 三、解析漏洞原理&.NET javascriptserializer反序列化漏洞：  
  
这个组件漏洞，是使用javascriptserializer序列化器，在网上net反序列化文章中多数提到，该库要利用反序列化漏洞必须满足一个条件，实例化 SimpleTypeResolver，但他并没有实例化 SimpleTypeResolver，还是能够rce，接下来一起分析一下：  
  
首先我们看一下常规的JavaScriptserializer反序列化漏洞  
  
使用ysoserial.net生成payload  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsuqeAcXrS7jlzc3dh5Sr517wPU2gsuDvchia0dqMKlWcg0QHE44j7PWw/640?wx_fmt=png&from=appmsg "")  
  
实例化了SimpleTypeResolver  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsOH0zTGGrOgc4r4mAnmA9WYeM8KpBXAVSE3SaYzIKeqAvs89WavZ02w/640?wx_fmt=png&from=appmsg "")  
  
目前yso默认打JavaScirptSerilize的只有ObjectDataProvider链，但是还有其他链能打，我们后面在说。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsYV4PQsiafv9bnOT4dicEfqdQKibnUcQAHDwMGoOoFVhealib9d277MlDaQ/640?wx_fmt=png&from=appmsg "")  
  
没有实例化SimpleTypeResolver  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsricF15XPz1V0wb2IK8ARw9mHxFAce1ZlXDw6ntcn29cBlOibm9ngicb8g/640?wx_fmt=png&from=appmsg "")  
  
报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsiaDibfzulgXdibB8Bw2YCDxZahzQ7iaJFQLnwqvrOmHuvFl1RmkYaMIiafQ/640?wx_fmt=png&from=appmsg "")  
  
原因简单点来说就是没有实例化SimpleTypeResolver 就不会使用类型解析器，也就是不会  
解析我们json中的_type的值，从而导致漏洞利用失败  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1Vs4GzqMiasVzhZQhzC2MwgxYzwHIUWnZJPXUDyyuhWho4G0UibguYxSqYw/640?wx_fmt=png&from=appmsg "")  
  
而一般开发者并不会实例化 SimpleTypeResolver，这个组件漏洞也是，但是为什么会存在漏洞呢？我们进入代码看看  
  
接受请求，首先调用EnsureSetup函数，然后判断是否是分块上传进行后续上传操作![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1Vs58GGaGiayO4GDN1nbgHPtksYTFUFiaUXkp26LicaIA16badHj0yR2nPGw/640?wx_fmt=png&from=appmsg "")  
  
  
EnsureSetup函数 ：判断一些属性然后赋值，其中将通过Context.Request() 函数获取rauPostData的值传入给GetConfiguration  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1Vs4Xl5WwiaEoicuRjmDRand3qJgicwZ5iaUJzMH78yjOdnrjlB7MFo6J1h9Q/640?wx_fmt=png&from=appmsg "")  
  
该函数就是漏洞的核心点：将传入的值以&进行分割，前一部分作为obj，后部分经过解密后作为Type一起传入Dserialize函数继续反序列化  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsZqxGq0hoTOQMguZBZZcnnDgCQjfNXBPq2aia1Bp2cpQlFl40KtyegXA/640?wx_fmt=png&from=appmsg "")  
  
跟踪来看该Dserialize函数反序列化方法实现就是通过反射调用的JavaScriptSerializer库进行反序列化，但是并未实例化SimpleTypeResolver，漏洞是如何触发的呢？还记得我们刚开始说的关键点 _type参数的内容是否会被解析  
，而该函数我们可以直接通过数据包传入type  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VslliagT5BePBxf20PJS2DY01ibM3IwaPQcce4ge0Ohtoy2ibrb6ticHSI3w/640?wx_fmt=png&from=appmsg "")  
  
因此是存在反序列化漏洞的  
#### 四、反序列化攻击利用链条：  
  
由上一节可知漏洞原理是没有实例化SimpleTypeResolver，而是从外部传入的type 所以不能使用ObjectDataProvider链和 System.Windows.Forms.BindingSource链。  
  
github公开的exp是使用 System.Configuration.Install.AssemblyInstaller 链条  
  
该链主要核心是设置path属性时会加载指定路径的程序集dll（正好该漏洞是上传文件功能，可以上传恶意dll到目标服务器）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsLlnqVwlh2F8eic4vQtpHPJIdGFuNUeIuia6w4wHkpgyzL7oDe6TQmGCw/640?wx_fmt=png&from=appmsg "")  
  
payload  

```
{
    &#34;__type&#34;: &#34;System.Configuration.Install.AssemblyInstaller,System.Configuration.Install, Version=4.0.0.0, Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a&#34;,
    &#34;Path&#34;: &#34;file:///E:\\sec\\NET\\calcdll\\calcdll\\bin\\calcdll.dll&#34;
}

```

  
注意：这个如果直接是net的dll，加载后不能触发静态构造函数，所以是不能进行rce的，需要结合HelpText属性中的getter方法触发构造函数从而rce(在实例化了 SimpleTypeResolver类可以用，这里是直接传入type使用不了)  
  
解决办法是在Assembly.LoadFrom加载的时候会执行DllMain() 进而加载 mixed assemblies（混合程序集）  
  
github中的payload也是这样写的：https://github.com/noperator/CVE-2019-18935  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsOATCpIO0WlYMOByNwqBGGKm353VV6kIZfE5l2cr70ib4EkakCe0vTiaw/640?wx_fmt=png&from=appmsg "")  
  
编译混合程序集  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VstloRH1r2iaGKqSy0ataTNOHqFUmrSye4Dbcb8ibtaGoExKHDPLsejewA/640?wx_fmt=png&from=appmsg "")  
  
简单来说就是可以将.NET 程序集注入 Windows 进程中来执行详细技术细节参考：https://thewover.github.io/Introducing-Donut/  
  
然后就可以通过加载该混合程序集dll执行命令了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsreFCZMKFgzQ1MOicfWHXOU8ABBQ5UmDxn363PGUbq3AIK7kuDSJPPSQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsAJ6fmMNIHyic1Yib88pibFubJZH9GqAicfGsRgDl13CdJSlW8WODrDOXbQ/640?wx_fmt=png&from=appmsg "")  
#### 五、waf绕过  
  
通过fuzz 发现该waf是针对该漏洞写的特殊规则  
1. rauPostDate值是加密后的序列化内容，此处检测from表单rauPostDate参数内容中&后有字符即拦截 原理就是上一节所说&后是TPYE的值也就是漏洞利用链输入的地方 而利用链system加密后正好是jyggli256.... 所以waf的规则也是按照该漏洞定制化的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsLQrhaCgkGuJ94BMtPickdwIOic36r6XuP9jhxnia0HObB3NmGNqmfnEcA/640?wx_fmt=png&from=appmsg "")  
1. 拦截漏洞利用路由 Telerik.Web.UI.WebResource.axd?type=rau  
  
传入时调用的是Context.Request() 方法，该方法是从所有请求中获取内容，我们就可以将rauPostDate参数从cookie中传入规避一下waf。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1Vs4Xl5WwiaEoicuRjmDRand3qJgicwZ5iaUJzMH78yjOdnrjlB7MFo6J1h9Q/640?wx_fmt=png&from=appmsg "")  
  
加密处只需要在system前加一个空格即可,加密后的内容即完全改变 不影响服务端解析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VswRPogiaP1mdicMlUoGRxACCmjf8OsI2icuibVtX3EdotOHSrVOemzHXUpQ/640?wx_fmt=png&from=appmsg "")  
  
数据包如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsRzkTFH3ECfuLNMw8y4wXsxq6GAefFbJq6DRhHJNBVkKuId4Foxyt0A/640?wx_fmt=png&from=appmsg "")  
  
3.拦截metadata 未加密的json值 此处检测metadata的值里有符号即拦截  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VslmCeYtaSFXBOibSzkB78LRGT5oNSLzWuHgBibbnjPqay1qM8SFvWosibw/640?wx_fmt=png&from=appmsg "")  
  
这个到后端本质还是需要反序列化为对象，为必要操作，不然无法正常上传dll文件，那么我们就可以将他加密以raupostdata发送以加密反序列化接口进行反序列化。  
  
调试出属性信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1VsGremHFyU6ZCtU8ETUFic7xyVZvhzTp6UfccPWnRaniaFUeibnREfFu6vA/640?wx_fmt=png&from=appmsg "")  
  
以加密接口进行发送反序列化绕过waf  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1Vsic1Op4ibq2cUjsqMVHfUSSNJLltbWhcsnQKLzbNiccuHOWl4GmxoZvUTA/640?wx_fmt=png&from=appmsg "")  
  
流量：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/T3Bzt8OABIYTPjodFfyydTRJaLS2L1Vs2WsS6Ko9EDicEmicSrsqoC7JD6iaLxhNecC8otT9hXSpzfJf2Wu3FBLnQ/640?wx_fmt=png&from=appmsg "")  
  
4.拦截上传dll时dll中的特征内容。  
  
这个就比较好处理了，直接用winhex替换头部特征即可，至此成功绕过某国际waf，原来的脚本exp发两个包，处理后发三个包，基本都是加密后的数据，waf很难识别。  
#### 六、内存马注入  
  
这块主要还是参考dust-life师傅的exp，是使用HostingCLR技术注入项目里也描述的很完善，我就不过多赘述了。  
  
https://github.com/dust-life/CVE-2019-18935-memShell  
### 参考  
  
https://github.com/noperator/CVE-2019-18935  
  
https://thewover.github.io/Introducing-Donut/  
  
https://github.com/dust-life/CVE-2019-18935-memShell  
  
  
