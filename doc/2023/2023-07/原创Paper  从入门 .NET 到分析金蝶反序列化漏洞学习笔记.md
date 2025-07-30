#  原创Paper | 从入门 .NET 到分析金蝶反序列化漏洞学习笔记   
原创 404实验室  知道创宇404实验室   2023-07-11 11:19  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3k9IT3oQhT1iaezR7tUcyEUGKhvic5YJ9ibO6O0kdKbpTj0siban0INVzQ36Y8ic7gibCGjNrX9qzbe5Kics4AOhKpoBA/640?wx_fmt=gif "")  
  
作者：  
Sunflower@知道创宇404实验室日期：2023年7月10日  
  
**1.前言**  
  
  
参考资料  
  
  
由于金蝶云星空能够使用 format 参数指定数据格式为二进制，攻击者可以通过发送由 BinaryFormatter 恶意序列化后的数据让服务端进行危险的 BinaryFormatter 反序列化操作。反序列化过程中没有对数据进行签名或校验，导致攻击者可以在未授权状态下进行服务器远程代码执行。  
  
  
刚接触 .NET 不久，正巧遇上了金蝶反序列化漏洞，本篇文章将从入门学习如何调试——分析金蝶反序列化漏洞  
  
  
**2.影响范围**  
  
  
参考资料  
  
金蝶云星空 < 6.2.1012.4  
  
7.0.352.16   
< 金蝶云星空 <7.7.0.202111  
  
8.0.0.202205 < 金蝶云星空 < 8.1.0.20221110  
  
**3.环境准备**  
  
  
参考资料  
  
  
**3.1 金蝶云星空**  
  
https://www.heshuyun.com/265.html   
  
  
本文选择漏洞版本 7.6，安装就不用说，下载地址里面都有。  
  
  
安装完成后访问能打开就行，如图 1 所示：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93aJApSTWqCVktgJVcDnvE54QmltdpUusaaicZfQj6dpO7PI6z2HMsNibw/640?wx_fmt=png "")  
  
图1 安装完成成功访问  
  
****  
**3.2 dnSpy**  
  
dnSpy 是一个调试器和 .NET 程序集编辑器。即使没有任何可用的源代码，你也可以使用它来编辑和调试程序集。  
  
  
https://github.com/dnSpy/dnSpy  
  
  
**3.3 Process Hacker**  
  
Process Hacker是一款免费、强大的多用途工具，可帮助你监控系统资源、调试软件和检测恶意软件。  
  
  
https://processhacker.sourceforge.io/  
  
  
  
**4.调试准备**  
  
  
参考资料  
  
  
已知漏洞的路径如下，现在需要通过该URL定位找到对应的代码位置。  
  
  
http://192.168.87.133/K3Cloud/Kingdee.BOS.ServiceFacade.ServicesStub.DevReportService.GetBusinessObjectData.common.kdsvc  
  
  
这是一个 .NET 程序，所以直接打开 IIS 管理器，右击 K3Cloud—— 浏览，找到源码的位置，如图 2 所示。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93Ul3hyltpjaAPQDiaMwFJmicNibxlsfD9Q390OL1QnJWtPlvBpL1yQADPA/640?wx_fmt=png "")  
  
图2 IIS管理器  
  
  
在 WebSite 目录下找到并打开 Web.config，如图3所示：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93WREnp4ZYo7ibud9UY3wZGrcrNgf4C1VoRH5opib2kkicdKPJSFAcVuA5g/640?wx_fmt=png "")  
  
图3 WebSite目录  
  
  
在 Web.config 的 handlers 中可以看到，其中定义了让路径为 kdsvc 结尾的请求去使用 Kingdee.BOS.ServiceFacade.KDServiceFx.KDServiceHandler 类进行处理，所以接下来寻找一下这个类的代码所在位置，如图 4 所示。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93Yv5QnOAyLlYfdTGrIN4OTJyrgFqrUiakdibicRudhHGEjloibTFzeHhJFg/640?wx_fmt=png "")  
  
图4 Web.config文件  
  
  
这里根据漏洞的 URL 推测，涉及的dll大概是 Kingdee.BOS* 这样的文件。从 WebSite\bin 目录下复制出 dll 文件，载入到 dnsPy 中，然后搜索：  
Kingdee.BOS.ServiceFacade.KDServiceFx.KDServiceHandle  
，  
如图 5，定位到代码具体位置：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93CTAbzATSocJRy520GOOTlsoJN9DS9v8Hcbib6nwJlzO5g3adPTLdAtA/640?wx_fmt=png "")  
  
图5 dnsPy搜索  
  
  
根据搜索已经知晓了是哪一个 dll 文件处理了（Kingdee.BOS.ServiceFacade.KDServiceFx.dll），接下来使用 Process Hacker 定位到该 dll 被调用时所在的位置，然后右击 Open file location。  
  
  
这一步有一个小坑，要先访问一遍漏洞路径，不然 Process Hacker 只能搜索出一个，并且这一个不能正确的进行调试。搜索出两个则选择包含 k3cloud 路径的那一个，如图 6。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93jdN8qgibMfr2syibMA9Gt6kAyIovjI6VAibRibTEV6XJkyHbd8sG3BbnibQ/640?wx_fmt=png "")  
  
图6 Process Hacker  
  
  
打开该 dll 的位置后，在该位置文件下新建一个同名 .ini 文件，如图 7 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93whcH3kaoMGLelGVN1EcgBRHHxjg1oTHGicx1ZKQWJh8XEcdSNAHWMfw/640?wx_fmt=png "")  
  
图7 dll文件位置  
  
  
文件内容如下，这里的作用是禁用编译优化 [1]（之后打开 cmd 使用 iisreset 命令重新 IIS 服务器，否则禁用编译优化不生效！）。  
  
```
[.NET Framework Debugging Control]
GenerateTrackingInfo=1
AllowOptimize=0
```  
  
重启完 IIS 服务器后，进程 ID 会改变，所以再次使用 Process Hacker 搜索到相应的进程 ID（打开文件夹验证同级目录下是否有刚刚创建的 .ini 文件），如图 8 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93rSe88BdxTGtyPxG6tdZmDPy774TsicquatcuBdZFV2K0ibCbFBBwxk3A/640?wx_fmt=png "")  
  
图8 Process Hacker  
  
接下来将这个目录下的 Kingdee.BOS.ServiceFacade.KDServiceFx.dll 文件加载到 dnsPy 中，调试——>附加到进程，选择刚刚得到的进程号 ID，如图 9 所示。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93XZc2IXggYgMV1y12ZaBxBPnI9cnzSfTQMsWh4tkZY6ngvtibeiaGv1ew/640?wx_fmt=png "")  
  
图9 dnsPy附加到进程  
  
  
接下来在 Kingdee.BOS.ServiceFacade.KDServiceFx的KDServiceHandler 中打上断点，稍等几秒看见断点变为实心红圈表示可以调试了，如图 10 所示。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93vvicUib7SoNhOaUUaEAmeqzwZ2SVxwYsIxwicFmUbtblw5H5E1mWuthxg/640?wx_fmt=png "")  
  
图10 dnsPy断点  
  
**5.漏洞分析**  
  
  
参考资料  
  
参考网上公开的 PoC[2]，将其中 PAYLOAD 位置替换为 ysoserial 生成的内容，先简要跟一下这个漏洞：  
```
POST /K3Cloud/Kingdee.BOS.ServiceFacade.ServicesStub.DevReportService.GetBusinessObjectData.common.kdsvc HTTP/1.1
Host: example.com
Content-Type: text/json

{
    "ap0":"PAYLOAD",
    "format":"3"
}
```  
  
这里直接发上面的数据包进行调试。如果之前配置的 dnSpy 没错，就可以成功断到点了  
，如图 11 所示  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93yLQL6gCeYDiaT0aLX9A8Y3qyIEY1hfy2DojqFjEoFgRPtFSIibPh8Wgw/640?wx_fmt=png "")  
  
图11 断点成功  
  
  
这里可以手动跳过几个系统的处理逻辑，ctrl+ 鼠标点击进入 return new KDSVCHandler();——this.ExecuteRequest(webCtx, requestExtractor);——RequestExcuteRuntime.StartRequest(requestExtractor, ctx);——RequestExcuteRuntime.BeginRquest(requestExtractor, context);，此时来到 RequestExcuteRuntime 类。断点断到 69 行 的 string localFile = webCtx.Context.Server.MapPath(path);，如图 12 所示。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93pSZxsPK8eB8TRcOgWiaNd7AbbToFcydrHHDBhSr6OrVdPevHK0MaZ4Q/640?wx_fmt=png "")  
  
  
图12 断点localFile  
  
  
这里的 path 就为我们传递的 url ，然后通过 webCtx.Context.Server.MapPath(path); 生成一个 localFile，BuidServiceType 方法根据 localFile 包含common.kdsvc，继续跳转到其他逻辑，如图 13 所示。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93PEicI7S028AyzmwnULMI3vNUjXtViaOiby9p28K3vickSfD79zT9COQ5Gg/640?wx_fmt=png "")  
  
图13 判断包含common.kdsvc  
  
  
通过处理赋值给 text 提取出类名和方法名等，再先通过缓存去查找类，没找到再调用 BuildServiceType 方法，如图 14 所示。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93wMVgNVwk8Y3uKFDVRRnkTCjJiaXacOntbdQD6r4MnfsLlyXH6qUrNVw/640?wx_fmt=png "")  
  
图14 通过缓存查找  
  
  
BuildServiceType 方法就是根据 strtype 定位到具体的程序集，然后再在程序集中寻找对应的类和方法等，如图 15 ，这里就不再细说。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93wveLyAEPd1xkzZCahLggvJ7g0BVic4nf3iaxdWbFhHHKwPLvgoKvs8FA/640?wx_fmt=png "")  
图15 寻找对应方法继续跟进，最终到达了 ExcuteRequest 方法内部，这里通过遍历几个 Modules 来处理这个请求，如图 16 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts935jHeWyms03hRbY9Yg4a5zibyIz5nhmNxaA8XEuMnETDzJAhJWW2nhHA/640?wx_fmt=png "")  
  
图16 ExcuteRequest方法  
  
  
差不多遍历到第 4 个 Modules ，进入到 OnProcess 方法中，如图 17 所示。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93jxxbA9g3oKyJAF1s3nl1xq6FfzfZSI7DZDzxvq2OWWHgAiadiaI3FuOg/640?wx_fmt=png "")  
  
  
图17 OnProcess方法  
  
  
再继续进入到 Execute() 方法内部，可以看到 DeserializeParameters() 方法，如图 18 所示。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93PmfZ8gI1zm8vE9o2hAnJA1pIgbE0XnvRqicCAnDPT5gU3NRyC0RxnWA/640?wx_fmt=png "")  
  
图18 Execute方法  
  
  
继续跟进，如图 19。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93ia4RRRcqIDMgpq62RYxF8tUoJiczAUAicQfoBEEiahxEGF6t8nVgQicJrSA/640?wx_fmt=png "")  
  
图19 DeserializeParameters方法  
  
  
直到最后跟进到 BinaryFormatterProxy 的 Deserialize 方法中，这里可以看出代码使用了   
BinaryFormatter  
   
进行  
了 Deserialize操作[2]，微软已经将 BinaryFormatter 的反序列化标注为不安全的[4]。  
```
    public object Deserialize(string content, Type type)
    {
        BinaryFormatter binaryFormatter = new BinaryFormatter();
        object result;
        try
        {
            byte[] array = this.encoder.Decoding(content);
            if (this.Compressor != null)
            {
                array = this.Compressor.Uncompress(array);
            }
            using (MemoryStream memoryStream = new MemoryStream(array))
            {
                result = binaryFormatter.Deserialize(memoryStream);
            }
        }
        catch (FormatException)
        {
            throw new KDException("#####", "服务器返回内容不能被解码，请检查服务器地址是否正确。");
        }
        return result;
```  
  
后调用栈如图 20 所示。  
  
  
  
  
  
最后调用栈如图 20 所示  
  
最后调用栈如图 20 所示最后调用栈如图 20 所示  
  
****  
图20 调用栈  
### 5.1 为什么要赋值format=3？  
  
因为 Create 方法中的 requestExtractor = new JQueryRequestExtractor(request, isGet);，其内部会根据 request 传递的值来进行属性的赋值给 this.form，如图 21 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93GODLHictPl2wa4EOJygDXUbCFe8ot7icXnxvxVr8neeFBS33yS7c8ibnw/640?wx_fmt=png "")  
  
图21 Create方法  
  
  
待后续调用到 this.Format 时，则会自动触发 Format 定义，如图 22 所示。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93CHPAj7ywwR9n60f6mY9t90k1eloICN9oghvDhupRXKZc5u5bicjzVgg/640?wx_fmt=png "")  
  
图22 Format定义  
  
  
如图 23，传递 format 参数为 3。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93IiapzBykavSdibrBNSTL8S3FAvVBrUGo10Tyb80c66au8S6sNicTATsLA/640?wx_fmt=png "")  
  
  
图23 调用到this.ExtractForm  
  
  
接下来根据这个属性值来进行匹配，为3正好能匹配到 Binary（当然这里 format 赋值为 Binary 也是可以的），如图 24 所示。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93Av7gzacPxMOg3sOTMzchvERbAOYhlGmXL2m0xm2mLib8YA7FXtC5ZHA/640?wx_fmt=png "")  
  
图24 format的取值  
**5.2 为什么使用ap0作为参数？**  
  
一开始以为 ap0 是 GetBusinessObjectData 其中一个参数，后来发现其使用了如下代码逻辑：  
```
  public string[] GetServiceParameters(string[] paras)
        {
            string[] array = new string[paras.Length];
            if (this.form.AllKeys.Contains("parameters"))
            {
                string parameters = this.form["parameters"];
                JSONArray jsonarray = new JSONArray(parameters);
                int num = Math.Min(jsonarray.Count, array.Length);
                for (int i = 0; i < num; i++)
                {
                    if (jsonarray[i] == null)
                    {
                        array[i] = string.Empty;
                    }
                    else
                    {
                        Type type = jsonarray[i].GetType();
                        if (type.IsValueType || type == typeof(string))
                        {
                            array[i] = jsonarray[i].ToString();
                        }
                        else
                        {
                            array[i] = jsonarray.GetJsonString(i);
                        }
                    }
                }
            }
            else
            {
                int num2 = 0;
                for (int j = 0; j < paras.Length; j++)
                {
                    array[j] = this.form[paras[j]];
                    if (array[j] == null)
                    {
                        array[j] = this.form["ap" + num2++];
                    }
                }
            }
            return array;
        }
```  
  
这意味着 array 只会接收 "ap+ 数字"和 parameters 中的值，否则 array 为 null 。此外，parameters 的值需要符合 JSON 格式。例如：  
```
{"ap0":"payload","parameters":["payload"]}
```  
  
  
**6.继续探索**  
  
  
参考资料  
  
  
分析到反序列化执行点发现，这里是先进行反序列化，之后 Invoke 再执行方法内部再进行参数类型判断。这就意味着不管调用哪个类或者方法，只要该类或者方法存在并且可以传入值（至少一个），那么都会调用到 this.DeserializeParameters(serializeProxy, svcType, paraValues) 代码里面，如图 25 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93CST6MYPfYwwOnV36WFuRN1xWicUYW2fkZusXfYOUQrzkWGFQjDoAYjw/640?wx_fmt=png "")  
  
图25 反序列化顺序  
  
此外还有个限制，svcType.MapToCLRType 的构造函数需要支持传递 context（KDServiceContext）类型或者继承该类型的参数。只有确保传递给 CreateInstance  
 方法的参数与所需的构造函数参数类型兼容，且符合构造函数的参数约束，才能成功创建对象，否则会在创建对象时报错，导致跳不到反序列化的步骤中去，如图 26 所示  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93sfKElWS11LicldXWNGNQAtNeoDGAmcRVEgKXkKO7TzkvEVibaro3Zrzg/640?wx_fmt=png "")  
  
图26 obj创建  
  
综上所述，只要任意一个类型的构造  
函数支持传递 KDServiceContext 类型或者继承该类型的参数，并且其中的方法可以传入参数（至少一个），那么都可以进入反序列化的代码逻辑里去。  
  
例举几个命名空间，他们下面的类的构造函数都支持传递 context 的类型：  
```
Kingdee.BOS.ServiceFacade.ServicesStubKingdee.BOS.ServiceFacade.ServicesStub.AccountKingdee.BOS.ServiceFacade.ServicesStub.WorkflowKingdee.BOS.ServiceFacade.ServicesStub.AppDesignerKingdee.BOS.ServiceFacade.ServicesStub.BaseDataKingdee.BOS.ServiceFacade.ServicesStub.BusinessDataKingdee.BOS.ServiceFacade.ServicesStub.BusinessFlowKingdee.BOS.ServiceFacade.ServicesStub.ComputingKingdee.BOS.ServiceFacade.ServicesStub.DataMigrationKingdee.BOS.ServiceFacade.ServicesStub.DBKingdee.BOS.ServiceFacade.ServicesStub.DynamicFormKingdee.BOS.ServiceFacade.ServicesStub.Metadata......
```  
  
调试到这里，成功跳到了反序列化步骤中去了，本以为可以准备收尾文章了，但是进入后发现 SerializerProxy 的 Deserialize 方法依旧对参数类型进行了判断。  
```
        public object Deserialize(string content, Type type)        {            if (string.IsNullOrEmpty(content))            {                if (type.IsValueType)                {                    return Activator.CreateInstance(type);                }                if (type.Equals(typeof(string)))                {                    return content;                }                return null;            }            else if (type == typeof(string))            {                if (this.proxy.RequireEncoding)                {                    byte[] array = this.proxy.Encoder.Decoding(content);                    return this.encoding.GetString(array, 0, array.Length);                }                return content;            }            else            {                if (type.IsEnum)                {                    return Enum.Parse(type, content, true);                }                if (type == typeof(int))                {                    return int.Parse(content);                }                if (type == typeof(byte))                {                    return byte.Parse(content);                }                if (type == typeof(float))                {                    return float.Parse(content);                }                if (type == typeof(double))                {                    return double.Parse(content);                }                if (type == typeof(long))                {                    return long.Parse(content);                }                if (type == typeof(DateTime))                {                    return DateTime.Parse(content);                }                if (type == typeof(decimal))                {                    return decimal.Parse(content);                }                if (type == typeof(bool))                {                    return bool.Parse(content);                }                return this.proxy.Deserialize(content, type);            }        }
```  
  
这里又出现了一层限制，因此正确的利用条件应该为：任意一个类型的构造函数支持传递 KDServiceContext 类型或者继承该类型的参数。该构造函数中的方法需要传入至少一个参数，并且参数不能为上述类型（string、int、byte、float...）。  
  
在我刚刚提供的命名空间里面还是能找到不少符合条件的，例如图 27。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93vxsIUAS3f2Qiaw00BlttohiaIDtSlIm3dYa9mEMos4BUO8jrDZqxibdZg/640?wx_fmt=png "")  
  
图27 符合条件的方法  
  
**6.1 构造其他PoC**  
  
这里只举了一个较为经典的案例，除此之外还有很多。  
  
Kingdee.BOS.ServiceFacade.ServicesStub.BusinessData.BusinessDataService.Audit 传递的第三个参数为 object[]（这里满足不为int、string等类型），且 ProcInstService 的构造函数支持传递 KDServiceContext 类型，满足条件，如图 28 所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93ee1V3pvTKsCYLMPOBibicZM2t7KyMTKFCRRg9EQo6zQnarJFxFiaptEeA/640?wx_fmt=png "")  
  
图28 符合条件方法举例  
  
之前提到的，传入 "ap+ 数字" 或者parameters，就可以给array赋值，这里Audit方法的第三个参数为object[]，所以就需要使array[2]为  
PAYLOAD，前两个值用ap0和ap1进行占位，ap2为PAYLOAD。  
  
所以构造的PoC 大致为：  
```
POST /K3Cloud/Kingdees.BOS.ServiceFacade.ServicesStub.BusinessData.BusinessDataService.Audit.common.kdsvc HTTP/1.1Host: example.comContent-Type: text/json{    "ap0":"1",    "ap1":"1",    "ap2":“PAYLOAD”,    "format":"Binary"}
```  
  
图 29 进行验证（这里PAYLOAD使用的是ysoserial生成的 ActivitySurrogateSelectorFromFile攻击链）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3k9IT3oQhT2wcviaue4ibkyq2oOwiaVts93lICnSKyGvAmbTsCdWWDkic95NJM7oTBjHG6PSSGH1h4EEibibibico5hGsQ/640?wx_fmt=png "")  
  
图29 漏洞验证  
  
  
**7.总结**  
  
  
参考资料  
  
  
本篇文章算是我从.NET入门到调试分析第一个漏洞，虽然一路上踩得坑还是不少，但是收获还是挺多的。本文主要讲了用 dnsPy 进行附加进程调试，至于VSstudio 调试以及一些编译优化入门可以看一下这篇文章：  
https://paper.seebug.org/1894/  
。  
  
  
**8.参考链接**  
  
  
参考资料  
  
  
[1]  
https://learn.microsoft.com/zh-cn/dotnet/framework/debug-trace-profile/making-an-image-easier-to-debug  
  
  
[2  
]  
https://mp.weixin.qq.com/s__biz=Mzg2ODYxMzY3OQ==&mid=2247498468&idx=2&sn=309198cc5bd645d5f7252288b5e629af  
  
  
[3]  
https://paper.seebug.org/901/  
  
  
[4]  
https://learn.microsoft.com/zh-cn/dotnet/standard/serialization/binaryformatter-security-guide  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3k9IT3oQhT0mSRTxbY7fsoLUFViaxk1nhQByibgTdbwbMqNibWMKbHKrjwUUY8GNZlAoUlcic5ibVhyCebVwoNialnow/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "404 logo-b04.png")  
  
  
**作者名片**  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0EJSbibGUh8VN6G4K6Peok7lDa0wDaBABAljmdwl0iaticu0Fd9WY2w2qmcIjpZBMEibcibZTzV00XaTQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3k9IT3oQhT0Z79Hq9GCticVica4ufkjk5xiarRicG97E3oEcibNSrgdGSsdicWibkc8ycazhQiaA81j3o0cvzR5x4kRIcQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**往 期 热 门**  
  
(点击图片跳转）  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650968843&idx=1&sn=9be8cc870827f4fbb6e99d60c5b3b9ac&chksm=8079d139b70e582fef34edc93be46b8734baddb8ce3b501adbcf8e43e7d9c7deb0daf62d213a&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650968840&idx=1&sn=7dab49b06f42b507bf8dcb8f5c95863f&chksm=8079d13ab70e582cc79f06b22957704f741940ca093d215f4b8226b91e6a9ce63dd41a5b0572&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650968804&idx=1&sn=f8365a4a90b7e179c5856f0d499fd5ad&chksm=8079d0d6b70e59c0a5a4fba1dcffa9486f59bd307c4336608c256e180868fe204d5dd3a1182e&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3k9IT3oQhT3BnohFTfovx8xftoWFTuCT1MRo5Dl4qusicddUyb4fhX04fIPFTcCbnZVpUHK0MJlhJfDJ1icZTqIA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3k9IT3oQhT3XlD8Odz1EaR5icjZWy3jb8ZZPdfjQiakDHOiclbpjhvaR2icn265LYMpu3CmR1GoX707tWhAVsMJrrQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
戳  
“阅读原文”  
更多精彩内容!  
  
  
