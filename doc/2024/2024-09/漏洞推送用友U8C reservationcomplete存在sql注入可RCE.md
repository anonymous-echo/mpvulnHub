#  漏洞推送|用友U8C reservationcomplete存在sql注入可RCE   
原创 小白菜安全  小白菜安全   2024-09-02 23:31  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞描述  
  
  
用友U8CRM-/bgt/reservationcomplete.php存在SQL注入漏洞，攻击者可通过此漏洞进行命令执行并且可通过该漏洞绕过登录访问后台。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
资产信息  
  
  
FOFA:  
title="用友U8CRM"  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia0024nVuRQwhCpY2PP9pKqqXMJbcLjK5TZMiaA4sib2Ebkb6A0yGPc73McSYJMOucev2rAGsjgAfWyQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现  
  
  
写入文件  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia0024nVuRQwhCpY2PP9pKqq4npXfuZS2avLQun5gwqqJ4yPtWhtGiacKvl9aVatX293mhvL8cTIpVA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia0024nVuRQwhCpY2PP9pKqqxAOuH2tojgdcCwqVg8vJ3Nxiat2SLvicFXSElylYdKS4vs72PEnEsC4g/640?wx_fmt=png&from=appmsg "")  
  
绕过登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia0024nVuRQwhCpY2PP9pKqq2GqOntWnkkH3Y9lLurYxZjox6mvkYr4KUHmshBcgo73C0wOBobQKPA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
POC获取  
  
  
关注公众号回复"  
2  
024  
0902"  
  
  
---------------------------------------------------  
  
加入内部圈子，回复“优惠卷”，福利限时发放。  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgOaSVwdVAPT7DWSKK7pjSWGdbQKWEM0yTB3JSqNxLUnEBesOW8eG40w/640?wx_fmt=png&from=appmsg "")  
  
免责声明  
  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgAth2WTu4kyEzL1Dia7AXUWcP7tsbHDtpaH1cls1lJTPVNE6XTwLYvJg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
