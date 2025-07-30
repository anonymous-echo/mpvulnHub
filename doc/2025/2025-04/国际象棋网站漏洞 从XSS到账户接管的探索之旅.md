#  国际象棋网站漏洞 从XSS到账户接管的探索之旅   
原创 子午猫  网络侦查研究院   2025-04-15 01:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bujwd3M0M1ICStsbhAHWtth8dQwoBBFoNDafDAzGbm1sCA8bqVWIjs40A8lu9rtuD4yeOOwDNadg/640?wx_fmt=png "")  
  
#   
## 前言  
  
在网络安全的世界里，每一次探索都是一次冒险。今天，我要分享的是一个关于如何发现并利用Chess.com漏洞的故事。这个过程充满了曲折和意外，但也正是这些意外，让我最终找到了那个“大奖”。  
## 背景：初次探索与XSS尝试  
  
2019年11月，我第一次开始研究Chess.com的漏洞。当时，我花了大量时间寻找通用的网络漏洞，但最初的尝试并不顺利。  
  
我找到了几个反射型XSS漏洞，但这些漏洞并没有带来太多乐趣。我尝试通过XSS钩子发送HTTP请求，将攻击者的Gmail账户绑定到受害者的Chess.com账户，理论上可以实现账户后门。然而，这并不能满足我对更严重漏洞的渴望。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2a2sI8Oxqu8Qg5WxL9R0B8PicfblHMlntHyfcHTxticAjrhvjubzmNnFhMoF42icFklWxNtXfjp5EgjQ/640?wx_fmt=png&from=appmsg "")  
  
img  
  
尽管如此，我并没有放弃。每次回头看这个项目，都像是在研究同样的功能，却从未发现任何新东西。直到有一天，我决定换一个角度思考。  
## 转折：发现新的子域名  
  
在一次偶然的机会中，我用iPhone和Burp Suite攻击另一家公司时，突然意识到我从未拦截过Chess.com应用的HTTP流量。当我打开Chess.com应用时，出现了一个我从未见过的新子域名——“api.chess.com”。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2a2sI8Oxqu8Qg5WxL9R0B8PWsyVfkI95S6sLgKdzjsAMsFVoh69gSGuVs3A3220sQjrXBdEoTQLBw/640?wx_fmt=png&from=appmsg "")  
  
img  
  
这个发现让我兴奋不已。我注意到，应用发送的每个请求都有正确格式的标头，并且确实有效。我开始研究这些请求的结构，发现“signed”参数被用作所有请求参数的哈希值。这意味着，如果我们能提取签名密钥，就可以任意签署请求。  
## 意外发现：用户信息泄露  
  
在探索过程中，我尝试搜索用户名“hikaru”并向其发送消息。这时，我发现了一个非常有趣的HTTP请求，它返回了用户的电子邮件地址！  
```
GET /v1/users?loginToken=98a16127fb8cb4dc97a3a02103706890&username=hikaru&signed=iOS3.9.7-7b9f1383b669614302e9503ba7db81875e440d7e HTTP/1.1Host: api.chess.com{"status": "success","data": {    "email": "REDACTED@REDACTED.COM",    "premium_status": 3,    "id": 15448422,    "uuid": "REDACTED",    "country_id": 2,    "avatar_url": "https://images.chesscomfiles.com/uploads/v1/user/15448422.90503d66.200x200o.f323efa57fd0.jpeg",    "last_login_date": REDACTED,    "session_id": "REDACTED",    "location": "Sunrise, Florida",    "username": "Hikaru",    "points": 52,    "chess_title": "GM",    "first_name": "Hikaru Nakamura",    "last_name": null,    "country_name": "United States",    "member_since": REDACTED,    "about": "",    "is_blocked": false,    "is_tracked": false,    "are_friends": false,    "friend_request_exists": true,    "is_able_to_change_username": null,    "flair_code": "diamond_traditional",    "show_ads": true,    "is_fair_play_agreed": true  }}
```  
  
这个发现让我意识到，可以任意获取任何用户的电子邮件地址，这可能是一个中等严重程度的漏洞。  
## 深入挖掘：Session ID的秘密  
  
在进一步研究中，我注意到每个用户的“session_id”值都不一样。这让我联想到，这些Session ID可能与用户的会话令牌有关。  
  
我在电脑上登录了Chess.com网站，并检查了我的Cookie。发现他们使用“PHPSESSID”作为会话令牌，而当我搜索自己的用户名时，它在“session_id”字段中返回的是我的“PHPSESSID”！  
```
HTTP/1.1 200 OKDate: Sat, 9 Dec 2020 05:52:47 GMTContent-Type: application/json..."session_id":"3947398c39ef15a.....56523b5a4533"...
```  
  
这意味着，我们可以通过这个漏洞提取任何用户的PHPSESSID cookie，从而劫持他们的会话。  
## 重大发现：管理员账户接管  
  
为了验证这个漏洞的影响，我继续检索了Chess.com管理员Daniel Rensch的PHPSESSID cookie。成功授权后，我尝试访问“admin.chess.com”子域。  
  
令我惊讶的是，我直接进入了管理员控制面板！这让我意识到，这个漏洞的严重性远超预期。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2a2sI8Oxqu8Qg5WxL9R0B8PficbCLzXcvE0ukUlsxedk9cINl2BSpvRasWN5q8DCLg1D0elbXKbWSQ/640?wx_fmt=png&from=appmsg "")  
  
img  
## 责任披露：及时报告漏洞  
  
意识到这个漏洞的严重性后，我立即编写并提交了漏洞报告。Chess.com的安全团队在一小时内回复了邮件，并迅速修复了漏洞。  
  
这次经历让我深刻体会到，作为安全研究人员，我们的目标是帮助互联网变得更安全。及时报告漏洞，不仅是对用户负责，也是对自己负责。  
## 结语  
  
这次漏洞发现之旅充满了意外和惊喜。从最初的XSS尝试，到最终的账户接管，每一步都让我对网络安全有了更深的理解。希望这个故事能激励更多人加入漏洞赏金计划，共同守护网络安全。  
  
**附录：漏洞发现的时间线**  
- **2019年11月**  
：初次探索Chess.com，发现反射型XSS漏洞。  
  
- **2020年12月**  
：偶然发现“api.chess.com”子域名，开始深入研究。  
  
- **2020年12月9日**  
：发现用户信息泄露和Session ID劫持漏洞。  
  
- **2020年12月10日**  
：成功接管管理员账户，提交漏洞报告。  
  
- **2020年12月10日**  
：Chess.com修复漏洞。  
  
**免责声明**  
：本文仅供安全研究和学习使用，请勿利用相关技术从事任何非法活动。作者不承担因使用此文所提供的信息而造成的任何直接或间接后果。  
  
  
  
**END**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bujwd3M0M1ICStsbhAHWtt0VVqCfFLOVnpmeNJ3R59doWtI0AmqLn4Qkic8aAS06l0pATjcYx10zw/640?wx_fmt=png "")  
  
  
