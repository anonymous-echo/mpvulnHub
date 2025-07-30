#  让 Deepseek 帮我写 POC，又快又准确！   
 黑白之道   2025-02-17 01:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
大家好，新年伊始，作为一个自由职业者，很多事情都需要自己一人完成，信安之路上线了 POC 管理系统，有大量漏洞需要转写成 Nuclei 所支持的 POC 模板文件，目前平台已收录四千多 POC 文件，还有不少 POC 未实现转换，如今 AI 的能力日渐强大，不依赖 AI 之力，作为科技从业者，也说不过去。  
  
在 AI 领域，Deepseek 的横空出世，引起不少社会关注，今天尝试使用其，帮我完成 POC 的编写，发现效果非常不错，只需要告知其目标，即可为我提供结果。  
  
以鸿运通天星系统的任意文件读取漏洞为例：  
```
下面是一个鸿运通天星系统的任意文件读取漏的数据包，如果返回内容中包括 <web-app 则认为该漏洞存在，请编写一个完整的模板：

GET /StandardApiAction_downLoad.action?path=/WEB-INF/web.xml HTTP/1.1
Host: tg.xazlsec.ru:8080
Content-Length: 0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
```  
  
Deepseek 直接将写好的 POC 告知，并进行了解释，如下：  
  
![image-20250213172028757](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfdA3tmFyfbMLanXPZV3iartg4ZdXeeIMPiaK0FFm5nk4FEYmQudohU3AYnFhDgPHL1R6IdRNhGBAQKQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
将结果中的 poc 保存到本地，先不看测试效果，先看看 poc 有没有语法错误，使用参数验证一下：  
> nuclei -duc -t hongyun-arbitrary-file-read.yaml -validate  
  
  
![image-20250213172141250](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfdA3tmFyfbMLanXPZV3iartgib4oVcDX5ibdu5wnkePVI8ady8Lp7SicJy69Zz1nibic6icljh3RvmjOuiahA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
测试无语法错误，那么尝试是否可以正确发现漏洞：  
  
![image-20250213172309569](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfdA3tmFyfbMLanXPZV3iartg4sTH7Efnze0R9H5NhoNlNSrPWKoh8xyWV5G9C7GA1cZaO2IQpjQH2w/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
最终发现漏洞存在，poc 无任何问题，所以直接使用 Deepseek 进行 POC 编写无任何问题，后面可以通过调用 API 完成自动化，为其提供数据包和验证方式，即可完成 POC 的编写，真正做到借助 AI 之力，达到事半功倍的效果。  
  
> **文章来源：信安之路**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
