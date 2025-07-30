#  使用AspDotNetWrapper复现反序列化漏洞   
专攻.NET安全的  dotNet安全矩阵   2024-01-13 08:35  
  
01  
  
**ASPDotNetWrapper >=.NET 4.5用法**  
  
AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata FKpYW56MFezy6wDm2/Cdy+c91Ki/J76QIqp9VCJfJLY6EolEbJuTRZTgpdJzUvgd2753UnF0LTlKOutQg7LusOQj11Q= --decrypt --purpose=viewstate --IISDirPath "/" --TargetPagePath "/About.aspx"  
  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1YicSiaqKJpS09zPSCI2FibEmzuEWNMdMfhHzy59sH2mvy19W0OOEUibO3o82Nib16YsC5vHuYXefJvpToA/640?wx_fmt=jpeg&from=appmsg "")  
  
02  
  
**欢迎加入我们的知识库**  
  
为了更好地应对基于.NET技术栈的风险识别和未知威胁，dotNet安全矩阵星球从创建以来一直聚焦于.NET领域的安全攻防技术，定位于高质量安全攻防星球社区，也得到了许多师傅们的支持和信任，通过星球深度连接入圈的师傅们，一起推动.NET安全高质量的向前发展。  
经过运营团队成员商议一致同意给到师傅们最大优惠力度，只需199元就可以加入我们。  
  
  
  
      
目前dot.Net安全矩阵星球已成为中国.NET安全领域最知名、最活跃的技术知识库之一，从.NET Framework到.NET Core，从Web应用到PC端软件应用，无论您是初学者还是经验丰富的开发人员，都能在这里找到对应的安全指南和最佳实践。  
  
    星球汇聚了各行业安全攻防技术大咖，并且每日分享.NET安全技术干货以及交流解答各类技术等问题，社区中发布很多高质量的.NET安全资源，可以说市面上很少见，都是干货。  
  
星球文化始终认为授人以鱼不如授人以渔！  
加入星球后可以跟星主和嘉宾们一对一提问交流，20+个专题栏目涵盖了点、线、面、体等知识面，助力师傅们快速成长！  
其中主题包括.NET Tricks、漏洞分析、内存马、代码审计、预编译、反序列化、webshell免杀、命令执行、C#工具库等等。![](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1YiccvW0LwqSx3grm4bgM0fz01qCxrYGBR94wibZ7sk1zIO9DzCgviab9vmUic8qmvynXhSM8LxFhGG97w/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1Y9y0BnibYCn1b9GMKqxd1Z5A1DLLJ9YxZeCn52XA1Kw7T5ibWCv89ZXpGjPOY7hXBDRVwNdKbMLZR3A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
    我们倾力打造专刊、视频等配套学习资源，循序渐进的方式引导加深安全攻防技术提高以及岗位内推等等服务。![](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1Y9XgicSeCfnDO0KyvDNdCZhG3pTSWHRekG0Wrp0FXyHO1mz9ia5uiaICjCmg5jIzx4ERLU8MjXWVSkCw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
    我们还有一个会员专属的星球陪伴群，加入的成员可以通过在群里提出问题或参与论的方式来与其他成员交流思想和经验。  
此外还可以通过星球或者微信群私聊向我们进行提问，以获取帮助迅速解决问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1YiccvW0LwqSx3grm4bgM0fz07qexJ82p5wxfXsVyzE3cc1WOVswovGicr35RthtQKpibYwibbSvicTRnjA/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1Y9aRFXpNeIkic3jTthR7HSTpiauTB4r1g5YUibqMhf1kyiczRTxl6JjlsztOXn7jlibsB4qYyXtCsz9ibiaQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NO8Q9ApS1Y9aRFXpNeIkic3jTthR7HSTpNnhbQiaxQFIWaF54HfVND1D7uVGeAgMYH7lnj65jBFtVA1q3ibWic03Ag/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![](https://mmbiz.qpic.cn/mmbiz_jpg/NO8Q9ApS1Y9lvf0EpBgVnMoicPtLAx2A1ls9pNaRTDZ9HLg88k7qk0Y188fdC6DHaful53ibicIFD6ib6Wl4vbaW9Q/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
