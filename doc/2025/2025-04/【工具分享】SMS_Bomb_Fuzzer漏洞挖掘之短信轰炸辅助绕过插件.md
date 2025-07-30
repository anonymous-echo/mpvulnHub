#  【工具分享】SMS_Bomb_Fuzzer漏洞挖掘之短信轰炸辅助绕过插件   
秀龙叔  黑客之道HackerWay   2025-04-27 09:58  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLGAg8Lt0lm8yqg0Nv50k55GLrcgC0RSiaRxxxvHkY7ec8BY4MwILFibn1qnMGepkmSHP4Vyon1eeAw/640?wx_fmt=png&from=appmsg "")  
  
简介：  
  
SMS_Bomb_Fuzzer是一个为Burpsuite设计的插件，主要用于辅助进行短信轰炸测试。它集成了多种绕过策略和数据变形方法，旨在帮助安全研究人员评估系统在面对恶意构造的请求时的安全性。该插件默认情况下是使用JDK 1.8版本进行编译的，这确保了其能够在广泛的应用环境中运行，并且能够与多数基于Java开发的安全工具兼容。  
  
插件功能：  
  
本Burp Suite插件专为短信轰炸漏洞检测设计，提供自动化Fuzz测试！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLGAg8Lt0lm8yqg0Nv50k55GLrcgC0RSiaRxxxvHkY7ec8BY4MwILFibn1qnMGepkmSHP4Vyon1eeAw/640?wx_fmt=png&from=appmsg "")  
  
绕过方式包含但不限于以下：  
```
参数污染
参数复用
参数编码
垃圾字符
特殊字符
号码区号
接口遍历
组合测试
XFF伪造
......
```  
  
安装使用：  
  
1、下载Releases中的SMS_Bomb_Fuzzer.jar然后将jar文件导入BurpSuite  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLGAg8Lt0lm8yqg0Nv50k55O2ZIQx9tpztIibhhgZ8KsD1Rhx7emBPh5HsmPuVIkpkVrXGx9VU2yog/640?wx_fmt=png&from=appmsg "")  
  
2、点击"Next"，导入成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLGAg8Lt0lm8yqg0Nv50k55WCMOIPTWvWIwNeSINXy4rzibI6wnibmK6MHncEMkAo4tnmtNYg6bUicGA/640?wx_fmt=png&from=appmsg "")  
  
3、  
将用于发送短信的数据包右键请求内容 → "Extensions" → "SMS Bomb Fuzzer" → "Send to SMS Bomb Fuzzer"  
  
![4](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLGAg8Lt0lm8yqg0Nv50k55m6VCMLMeicfhDXqOxVUQr8HiaRsyc2dUcv677EcssepNkxareCRt04Gg/640?wx_fmt=png&from=appmsg "")  
  
4、开始测试并分析响应（测试完成状态会变化）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLGAg8Lt0lm8yqg0Nv50k55GLrcgC0RSiaRxxxvHkY7ec8BY4MwILFibn1qnMGepkmSHP4Vyon1eeAw/640?wx_fmt=png&from=appmsg "")  
  
- 公众号回复“  
6586  
”获取下载链接  
  
**用您发财的小手点个赞鼓励一下吧❥(^_-)**  
  
**关注公众号便于更好的为您分享(#^.^#)**  
  
  
  
  
**免责****声明**  
  
本公众号“黑客之道HackerWay”提供的资源仅供学习，利⽤本公众号“黑客之道HackerWay”所提供的信息而造成的任何直接或者间接的后果及损失，均由使⽤者本⼈负责，本公众号“黑客之道HackerWay”及作者不为此承担任何责任，一旦造成后果请自行承担责任！  
  
  
谢谢 !  
  
