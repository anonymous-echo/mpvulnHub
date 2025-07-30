#  FUZZ出来的一系列漏洞   
原创 hacker30  hacker30   2025-02-02 12:43  
  
**前言：在平常挖洞过程中，不乏很快就能出成果，也不乏测试很长一段时间都一无所获，心态容易受到影响，陷入自我怀疑。但我们只需要静下心来，充分利用收集的所有信息，多尝试新的思路，也许就会有出其不意的效果。**  
  
1、在访问测试站点时，抓取到这么一个接口的数据包：  
```
/xxx-athene/system/login
```  
  
尝试对一级路径/xxx-athene/进行目录遍历，没啥可利用信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5pwHn9fR3RlDyzwaHiboHSPT4C1Xj7oXbbPnGJsIRdaf1wtuiaRpibLhiavBDVENia9S2GB6ibibV1XtIj7IsiaL2DnN1w/640?wx_fmt=png&from=appmsg "")  
  
2、抱着试一试的心态去FUZZ路径  
/xxx-athene/中的  
athene，效果如下，出来了以下路径：  
```
/xxx-crm/
/xxx-preview/
/xxx-file/
/xxx-application/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5pwHn9fR3RnH46vJvCFHOgCKV5Y3UaCdyYib4lY64qZS1llflJLpzqWDJGjwrzgtwicazQ4R4m3NpYMVdVEeqY8w/640?wx_fmt=png&from=appmsg "")  
  
再对FUZZ出来的路径进行目录遍历，swagger接口文档就这么水灵灵的出来了。  
然后对接口进行未授权测试，很可惜都鉴权了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5pwHn9fR3RlDyzwaHiboHSPT4C1Xj7oXbzurVEQU51etQyXIHpBnM909dsQRshf0gWibrXQnibAloCBqAE2ojUtDQ/640?wx_fmt=png&from=appmsg "")  
  
3、接着对路径/xxx-preview/进行目录扫描，发现了/index路径，浏览器一拼接访问，kkfileview映入眼帘：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5pwHn9fR3RlDyzwaHiboHSPT4C1Xj7oXbqQsE3ibx7vibc1f8sV1qpsNMt5fxZLVr7FVJbqFJRmUuibLCMG12JqG6A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5pwHn9fR3RlDyzwaHiboHSPT4C1Xj7oXbmjX44QAFr8UqhvA3mjLnbhsI0bQK6Yoico6ic5KK2sTDM9oPpHib0nYuA/640?wx_fmt=png&from=appmsg "")  
  
测试了远程代码执行和任意文件读取都没成功。  
  
4、但发现是个全回显ssrf漏洞，只能使用http/https协议，file、gopher协议使用被waf拦截：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5pwHn9fR3RnH46vJvCFHOgCKV5Y3UaCd8EnF9SFwRXB5ufS4YHPZ0FFTyBhS8gV59oBCpouicmQsLB2XKOayicnQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5pwHn9fR3RlDyzwaHiboHSPT4C1Xj7oXbL9WwCuHoq9UkUt5olWqpb7OicFOTcwz7IpEic60zvYfu35N7RwIzzYZw/640?wx_fmt=png&from=appmsg "")  
  
后面也是挖掘到了敏感信息泄露，grafana未授权等漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5pwHn9fR3RlDyzwaHiboHSPT4C1Xj7oXbibJ5TNpc4u1cibydlCalkP3yDcntLPYiapEIqicwic0gTsgwRRKImwjfsbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5pwHn9fR3RlDyzwaHiboHSPT4C1Xj7oXbugMqAb4KmuYpykGVYBX5PUtTJqj18KvCuliblAXuhN4pUqk3koiaXafw/640?wx_fmt=png&from=appmsg "")  
  
