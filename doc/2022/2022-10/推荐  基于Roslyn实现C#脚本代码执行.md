#  推荐 | 基于Roslyn实现C#脚本代码执行   
专攻.NET安全的  dotNet安全矩阵   2022-10-18 09:00  
  
# 0x01 背景  
  
  
有些情况下需要在程序运行期间动态执行C#代码，从C# 6 开始利用Roslyn编译器可以方便地在我们的程序中动态编译代码，具体的版本信息是.NET 4.6及.NET Core均支持，假定在渗透过程中目标站点已经具备了Roslyn环境时，可以尝试使用CSharpScript.EvaluateAsync方法执行需要编译的代码内容，编译时需引入ScriptOptions.Default.WithReferences提供必备的程序集文件，执行后效果如图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1Yicc7ldqBSFNuDCwTUqTiaUoSEuVibFuXtiakHOGBUGfibbH3QAxfffWYCwnNb26DaCw91Ue4iayGEAVLxw/640?wx_fmt=png "")  
## 1.1 原理分析  
  
  
查看站点是否安装了  
Roslyn环境，一般只需关注是否存在  
Microsoft.CodeAnalysis.CSharp.dll，通常在代码里会引入以下命名空间，  
```
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
```  
  
EvaluateAsync以异步线程任务的方式返回脚本执行后的结果，第二个参数项ScriptOptions.Default.WithReferences 表示引入的程序集  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1YicFnzoBLCC3n5u7eicEFtOa3LnTm6Dl8rW09WcmqGicibmuQvqwjTA93WiawHW4AykYEg7JwmxfWd8f5g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1YicFnzoBLCC3n5u7eicEFtOa3Cvvd5iaMdZzrbhGxooMGjLPbd0dYWwv8L71HzfwMOiaMdPqqPhqDLnMg/640?wx_fmt=png "")  
## 1.2 使用场景  
  
  
以弹出计算器作为demo，但这样在实战中看不到命令返回的结果，所以笔者改造后如下图  
```
await CSharpScript.EvaluateAsync("System.Diagnostics.Process.Start(\"calc\")", ScriptOptions.Default.WithReferences(typeof(System.Diagnostics.Process).Assembly));
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1YicFnzoBLCC3n5u7eicEFtOa3krJ8qoNjLLoaw75ia3nrtKbwD7wd3cib5LibfdZxHGj7Uz7xcQ4O2EVYA/640?wx_fmt=png "")  
  
**脚本工具已打包在星球，感兴趣的师傅可以自行研究测试。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1YicFnzoBLCC3n5u7eicEFtOa3riazPtLepc46hyTyMUPJlAoicIozSSliaOkR5m7SUVU6wiafC9ib38aCdEw/640?wx_fmt=jpeg "")  
# 0x02 星球优惠活动  
  
为了更好地应对基于.NET技术栈的风险识别和未知威胁，dotNet安全矩阵星球从创建以来一直  
聚焦于.NET领域的安全攻防技术，定位于  
高质量安全攻防星球社区，也  
得到了许多师傅们的支持和信任，通过星球深度连接入圈的师傅们，一起推动.NET安全高质量的向前发展  
。  
**星球提供50元代金劵，师傅们先到先得噢！扫描星球亮点里的二维码即可加入我们。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1YibuxMvdKPXjjMPhQjaCh2vwvLYKIWu5xbbR52F3JahJNvjfDw1jd3gy5Kgwh92quxrtlluFs0sIdQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
星球汇聚了  
各行业安全攻防技术大咖，并且每日分享.NET安全技术干货以及交流解答各类技术等问题，社区中发布**很多高质量的.NET**  
安全资源，可以说市面上很少见，都是干货。其中主题包括  
**.NET Tricks、漏洞分析、内存马、代码审计、预编译、反序列化、webshell免杀、命令执行、C#工具库**  
等等，后续还会倾力打造  
**专刊、视频**  
等配套学习资源，循序渐进的方式引导加深安全攻防技术提高以及岗位内推等等服务。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1Y8DlZsGiaRRGghficKFQt58Ueoynsb0my3uzMAb7VwM5bgtnb4nbl4c9xdEjGraUXic6pO0p38xmWiaRQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1YibHErRN3IhgSaicia7Rl5SF0plpcuicd0KG8Cn7vGczlBRtvSJvicWejH7TOro6AGLQ627SvVzxzBnphg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1Y8DlZsGiaRRGghficKFQt58UeoxTMuRezdHEJu6Hp08Xgm2F49cyBI1zlcj5XqLJK8zedWlUjibYmia3g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
dotNet安全  
矩阵知识星球 —   
聚焦于微软.NET安全技术，关注基于.NET衍生出的各种  
红蓝攻防对抗技术、分享内容不限于 .NET代码审计、 最新的.NET漏洞分析、反序列化漏洞研  
究、有  
趣的.NET安全Trick、.NET开源软件分享、. NET生  
态等热点话题、  
还可以  
获得阿里、蚂蚁、字节等  
大厂内推的  
机会.  
  
