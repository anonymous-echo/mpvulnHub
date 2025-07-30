> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247494938&idx=1&sn=91a67ca633418f9dcb55b495272f75ab

#  插件推荐 | 哥斯拉一键注入正向代理suo5内存马  
X1r0z  星落安全团队   2025-06-17 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/spc4mP9cfo75FXwfFhKxbGU93Z4H0tgt4O9libYH9mKfZdHgvke0CeibvXDtNcdaqamRk3dEEcRQiaWbGiacZ2waVw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WN0ZdfFXY80dA2Z4y8cq7zy2dicHmWOIib5sIn8xAxRIzJibo2fwVZ3aicVBM8RnAqRPH5Libr4f02Zs5YnMLBcREnA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
现在只对常读和星标的公众号才展示大图推送，建议大家能把  
**星落安全团队**  
“  
**设为星标**  
”，  
否则可能就看不到了啦  
！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllkXnsUODwVWmlxAHuHu4dBuwIlu707ZfPdbNTYyibYzQHA0xn0p2hTbQAiba04SOnDiadxVExZ53nfog/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**工具介绍**  
  
Suo5MemShell一款哥斯拉后渗透插件，支持一键注入suo5内存马。  
  
目前支持的中间件和内存马类型：  

```
Tomcat  Filter/Servlet
Spring  Controller
WebLogic  Filter
Jetty  Filter
Resin  Filter
JBoss/WildFly Filter
```

  
部分中间件的兼容性支持：  

```
Tomcat 5 - 10Jetty 7 - 11.0.11JBoss (WildFly) 8 - 27.0.0Resin 3 - 4.0.66WebLogic 10.3.6 - 14
```

  
  
**使用方法**  
  
内存马注入部分参考了 Godzilla 内置的 FilterShell 和 MemoryShell 插件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllkVBzC7X1iaKtRSoJCicAXquDgXXML6bEC2pYvE8NIibiaO221LRDRkgLiaAIHnIG3NzMu3xkgFFl3QqJg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllkVBzC7X1iaKtRSoJCicAXquDEZz8O1H8sIb3EQa0iaVtuR88CbzUCLDZPXXmt6KHyoA9SaA3FzFib0RA/640?wx_fmt=png&from=appmsg "")  
### 注入 Tomcat Filter 内存马  
### 需要指定 urlPattern, 一般不建议设置为 /*  
### filterName 为可选项, 如果为空则使用 Godzilla 默认生成的随机名称  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllkVBzC7X1iaKtRSoJCicAXquD5gMicRXm4LZiaeyJgQCCjoXTiafKzGN5QAfBaPKz21RVuRZpYYvhRicjTg/640?wx_fmt=png&from=appmsg "")  
  
在 Godzilla 自带的 FilterShell 插件中可以看到注入的 Filter 内存马  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllkVBzC7X1iaKtRSoJCicAXquDXWGr1XdSKlL1VIV9eQnW7aNMPiacOT0JpghTv5At9kIXINoA0gib8TNw/640?wx_fmt=png&from=appmsg "")  
### 注入 Tomcat Servlet 内存马  
### 需要指定 urlPattern  
  
wrapperName 为可选项, 如果为空则使用 Godzilla 默认生成的随机名称  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllkVBzC7X1iaKtRSoJCicAXquDLN2L5Nmk8FY53ia4p4VyNjPDwPHFnW1hMxDw6GZcjlJZaynpsAIx06Q/640?wx_fmt=png&from=appmsg "")  
  
在 Godzilla 自带的 ServletManage 插件中可以看到注入的 Servlet 内存马  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllkVBzC7X1iaKtRSoJCicAXquDN9Z3ibW4YAnUiaxhXw80KxW8ggdshxeoFsdn6JMekibQicPRib5u6Y8ybSg/640?wx_fmt=png&from=appmsg "")  
### 注入 Spring Controller 内存马  
### 仅支持基于 Servlet API 的 Spring 应用  
  
需要指定 urlPattern  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllkVBzC7X1iaKtRSoJCicAXquDvTssBB0FvzCurDovuatfCIsicnsEiaTdQTo6mlc1mpSLpJKT9SUEtKHw/640?wx_fmt=png&from=appmsg "")  
### Others  
### 以下内存马的注入仅需配置 urlPattern 参数, 暂不支持卸载  

```
WebLogic Filter
Jetty Filter
Resin Filter
JBoss/WildFly Filter
```

## Compile  
## 1. GitHub Releases 页面提供了基于 JDK8 编译的 jar 包。当然你也可以选择自己手动编译，首先克隆本项目  

```
git clone https://github.com/X1r0z/Godzilla-Suo5MemShell
```

  
2. 修改 pom.xml 中 godzilla 依赖的 systemPath 为自己本地的路径  

```
<dependency>
    <groupId>godzilla</groupId>
    <artifactId>godzilla</artifactId>
    <version>0.1.0</version>
    <scope>system</scope>
    <systemPath>/Users/exp10it/Downloads/godzilla.jar</systemPath>
</dependency>
```

  
3. 在当前项目目录执行如下命令，  
生成的 jar 位于 
```
target
```

  
 目录  

```
mvn package -Dmaven.test.skip=true
```

  
  
**相关地址**  
  
**关注微信公众号后台回复“入群”，即可进入星落安全交流群！**  
  
**关注微信公众号后台回复“20250618”，即可获取项目下载地址！**  
  
****  
  
  
**圈子介绍**  
  
博主介绍  
：  
  
  
目前工作在某安全公司攻防实验室，一线攻击队选手。自2022-2024年总计参加过30+次省/市级攻防演练，擅长工具开发、免杀、代码审计、信息收集、内网渗透等安全技术。  
  
  
目前已经更新的免杀内容：  
- 部分免杀项目源代码  
  
- 一键击溃360+核晶  
  
- 一键击溃windows defender  
  
- 一键击溃火绒进程  
  
-    
CobaltStrike4.9.1二开   
  
-    
CobaltStrike免杀加载器  
  
- 数据库直连工具免杀版  
  
- aspx文件自动上线cobaltbrike  
  
- jsp文件  
自动上线cobaltbrike  
  
- 哥斯拉免杀工具   
XlByPassGodzilla  
  
- 冰蝎免杀工具 XlByPassBehinder  
  
- 冰蝎星落专版 xlbehinder  
  
- 正向代理工具 xleoreg  
  
- 反向代理工具xlfrc  
  
- 内网扫描工具 xlscan  
  
- CS免杀加载器 xlbpcs  
  
- Todesk/向日葵密码读取工具  
  
- 导出lsass内存工具 xlrls  
  
- 绕过WAF免杀工具 ByPassWAF  
  
- 等等...  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/DWntM1sE7icZvkNdicBYEs6uicWp0yXACpt25KZIiciaY7ceKVwuzibYLSoup8ib3Aghm4KviaLyknWsYwTHv3euItxyCQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
目前星球已满600人，价格由208元  
调整为  
218元(  
交个朋友啦  
)，700名以后涨价至268元！  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/rlSBJ0flllmhbpbKayuoesboibwWNPhDnEwqZ2QqleN4icUYQaMEf2cZagicoU0PaWsNo1r5tybdzczRhiaEBCicvYA/640?wx_fmt=jpeg&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/MuoJjD4x9x3siaaGcOb598S56dSGAkNBwpF7IKjfj1vFmfagbF6iaiceKY4RGibdwBzJyeLS59NlowRF39EPwSCbeQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
     
往期推荐  
     
  
  
1.   
[学不会全额退款 | 星落免杀第一期，助你打造专属免杀武器库](https://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247494072&idx=1&sn=e46a6d176a8fad2aa4b4c055de3607da&scene=21#wechat_redirect)  
  
  
  
2.   
[【干货】你不得不学习的内网渗透手法](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247489483&idx=1&sn=0cbeb449e56db1ae48abfb924ffd0b43&chksm=c0e2bc74f79535622f39166c8ed17d5fe5a2bbc3f622d20491033b6aa61d26d789e59bab5b79&scene=21#wechat_redirect)  
  
  
  
3.   
[【免杀】CobaltStrike4.9.1二开 | 自破解 免杀 修复BUG](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247488486&idx=1&sn=683083d38a58de4a95750673d9cb725d&chksm=c0e2b859f795314f3b7bc980a5d4114508ee2c286bc683cdfd25eefa4fb59f26adfe5483690b&scene=21#wechat_redirect)  
[！](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247486966&idx=1&sn=3f144d5936d5cdc11178004549384ace&chksm=c0e2a649f7952f5f7557dde6e9cca53ecee7b5e2f7ff23395250e8fe47acb102902d9727185d&scene=21#wechat_redirect)  
  
  
  
4.   
[【免杀】原来SQL注入也可以绕过杀软执行shellcode上CoblatStrike](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247489950&idx=1&sn=a54e05e31a2970950ad47800606c80ff&chksm=c0e2b221f7953b37b5d7b1a8e259a440c1ee7127d535b2c24a5c6c2f2e773ac2a4df43a55696&scene=21#wechat_redirect)  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/DWntM1sE7icZvkNdicBYEs6uicWp0yXACpt25KZIiciaY7ceKVwuzibYLSoup8ib3Aghm4KviaLyknWsYwTHv3euItxyCQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
【  
声明  
】本文所涉及的技术、思路和工具仅用于安全测试和防御研究，切勿将其用于非法入侵或攻击他人系统以及盈利等目的，一切后果由操作者自行承担！！！  
  
