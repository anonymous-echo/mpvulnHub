#  意外发现谷歌Slides越权漏洞，获得赏金$3133.70的故事   
 Z2O安全攻防   2025-01-20 13:03  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;"><span leaf="">声明：</span></span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;"><span leaf="">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></span></h1></td></tr></tbody></table>  
背景介绍  
  
某一天悠闲的午后，白帽小哥Atikqur坐在办公桌前，在 Google Slides 上准备着一场活动的演讲稿。  
  
幻灯片准备好后，开始点击演示者视图来预览它们，由于白帽小哥想与观众进行现场问答环节，因此他开始在网上搜索 Google Slides 是否有此类功能。  
  
就在此时，偶然间发现了“观众工具”这项功能，要启用该功能的话，需要进入演示者视图，然后点击观众工具，然后点击“开始”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkw1I6Y5F8f5LYtbtic0bu4xaX23UQ53s2D3Xwk89I0rjmzt4QVJHvR4Tq1oIRPE3E6v4cHYUUXpGA/640?wx_fmt=png&from=appmsg "")  
# 漏洞发现  
  
开始会议后，你会收到一个链接，观众可以在你演示时使用该链接实时提出问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkw1I6Y5F8f5LYtbtic0bu4xZ3MjtFqvQxVc4uQlo41IU09PW0zj6oNicYZa6SduU3SEy8UD38iaXVeQ/640?wx_fmt=png&from=appmsg "")  
  
好奇之下，白帽小哥复制了链接并在 Chrome 的无痕模式下打开，以探索观众如何进行提问。  
  
原来任何人都可以提问，并且无需登录！问题框的用户界面看起来有点过时，于是小哥的漏洞挖掘本能被成功“激活”…  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkw1I6Y5F8f5LYtbtic0bu4xYoT1ddicjhzXmEPUqIuiaSJVbu8MlKfzSW8DYm5hbPqvvgG19fT6k9cg/640?wx_fmt=png&from=appmsg "")  
  
没有片刻犹豫，启动 Burp Suite 开始抓包，小哥注意到每次有人问问题时，POST 请求中都会包含一个唯一的 clientId。  
```
POST /presentation/d/e/2QANgcCBH8YIx_f5yfCz0l5len6p5BDFsiROx_rcqbOqYgcByotn7pOpaS3kXb3YYffwepoOXCyzanE8ZCIw/submitquestion?includes_info_params=1 HTTP/1.1Host: docs.google.comCookie: Content-Length: 84Content-Type: application/x-www-form-urlencoded;charset=UTF-8Accept: */*Origin: https://docs.google.comReferer: https://docs.google.com/presentation/d/e/2QANgcCBH8YIx_f5yfCz0l5len6p5BDFsiROx_rcqbOqYgcByotn7pOpaS3kXb3YYffwepoOXCyzanE8ZCIw/askquestion?seriesId=d90df436-a253-48a1-8aea-bf5c19761447Accept-Encoding: gzip, deflate, brAccept-Language: en-US,en;q=0.9Priority: u=1, iConnection: keep-aliveseriesId=d90df436-a253-48a1-8aea-bf5c19761447&clientId=e5j7slqfku2&questionText=Test
```  
  
因此每一条提问都有一个唯一的clientId ——这可能会存在一个潜在的漏洞！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkw1I6Y5F8f5LYtbtic0bu4x4VloiccVZy8PA6jqHuLyEWv1IJUBr3kGHnlrJwKBJVp9ibmPe6rfNn4A/640?wx_fmt=png&from=appmsg "")  
  
任何人点击链接，所有问题都会加载带有唯一 clientId 的提问。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkw1I6Y5F8f5LYtbtic0bu4xIsZoILib29EpEgjd5CXsCpusLOsWBpTbgztx221HSx3vvXJ0VBCEQZg/640?wx_fmt=png&from=appmsg "")  
  
白帽小哥立即明白了这里可能存在什么样的BUG，小哥登录了两个不同的帐户，并从帐户 1 提交了一个问题“Test”。  
  
然后，在另一个浏览器中使用 account-2，复制了 account-1 提问的 clientId，然后拦截account-2提交问题时的请求，然后将其clientId替换为account-1的clientId。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkw1I6Y5F8f5LYtbtic0bu4xqoEzsuPzDiaKhRjk9h4tvKHQe5wsuVCzuQvnxxEt0xnC5NuVO8Ir2FQ/640?wx_fmt=png&from=appmsg "")  
  
账户-1 提交的问题成功地被账户-2 的请求修改了，更关键的是，这甚至可以在不登录的情况下被利用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkw1I6Y5F8f5LYtbtic0bu4xN3A3llP1nIcD4nU9KVx7LtcktibG5tSE92vJdJnql1ia2lRERqGJKEPw/640?wx_fmt=png&from=appmsg "")  
  
小哥立即向谷歌报告了此事，谷歌第二天就关闭了该报告，并称安全风险极小（不予修复）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkw1I6Y5F8f5LYtbtic0bu4xWg4rGm08tVHr1tStbFuOcYe2tl0UToXM4g83uWozYSBOEBxK9rSmDA/640?wx_fmt=png&from=appmsg "")  
  
但小哥知道这个漏洞的影响是明显的：无需用户交互即可利用它，也无需猜测或暴力破解 clientId，因为应用程序本身就提供了 clientId。  
  
小哥礼貌地重申了关于该漏洞的观点，谷歌重新打开了问题并确认了它，然而十天后，报告再次被关闭，理由是由于“猜测”clientId，安全风险仍然很低。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkw1I6Y5F8f5LYtbtic0bu4xJeSf51mvIYrfHpVCurQxiajlictXIJibFmiaopVqccnyjuOYqJJ4Xlz79g/640?wx_fmt=png&from=appmsg "")  
  
小哥有些失望，猜测谷歌的安全团队并没有正确测试该漏洞，甚至他们可能都没有查看小哥提供的 PoC 演示视频，因为clientId是由应用程序本身自动加载的，因此根本没有必要去猜测clientId。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubYoDpEiaibMCSNicx1wtZiaTAW5CSX75jBJh8HfmLO7lmZFA2P9SXDMzATcw5SYeXw1Jex8CsGHd7BQQ/640?wx_fmt=png&from=appmsg "")  
  
白帽小哥再次解释了这一点，并展示了攻击者如何毫不费力地提取clientId，最终谷歌的安全团队复现了该漏洞，并承认了漏洞影响，最终按照 S2 严重性类别奖励了小哥 3133.70 美元。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jkw1I6Y5F8f5LYtbtic0bu4xDcdd8bG57cmKhHAc4zzQaXQYKEwXyOs4TRNZMdgJD31zSJSxQ7Ydyw/640?wx_fmt=png&from=appmsg "")  
  
原文：  
https://medium.com/@atikqur007/how-i-accidentally-found-an-idor-bug-in-google-slides-and-rewarded-3-133-70-96866fac3af1  
  
建立了一个  
src专项圈子，内容包含**src漏洞知识库**、**src挖掘技巧**、**src视频教程**等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg41LkR0ezBlmjJY4Lwgg8mr1A5efwqe0yGE9KTQwLPJTe9zyv3wgYnhA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOXg868PqXyjsACp9LhuEeyfB2kTZVOt5Pz48txg7ueRUvDdeefTNKdg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuY6DfYOuUzWiaPBBq4L5bV9ZRMpUcFktl9oiazJicibKEVwZoWo5dEaXGHIoa6yOEkfnicbMibJDALxuk1w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4Bd1oBmTkA5xlNwZM5fLghYeibMBttWrf57h8sU7xDyTe5udCNicuHo8w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYrUoo5XZpxN9Inq87ic71D6aUeMdaWrKXgYYia2On8nMA7bqWDySa8odAq1a0kkp3WFgf0Zp0Eut0A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4KKlic4yiafWTpLdejicQe3MllEQc24ypeI3anaK7IjJDVyq1WVQN2yKBA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOHgjJxnq1ibibJgVUx3LwCjZj62vygx8w6rxia1icmIWiax2YlP6S6LmlmlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOApVm8H605qOibxia5DqPHfbWD6lmcweDjGv4DLl45waD068ugw2Iv2vg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOwldaSATYOh1WQpk1qz15rLxehOAn4aK7tdbSyNEuHDZpIISCtl6Q8w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4jFsKRMMNDKbsAZhscCiagnyJScMVmFUqMtae5omlLRdu095mywWszjQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4uGJ2SA5BhZ3UyibZvVmcP3sozQEOfVr0jftWpC3YkpDiaAicS1ib3EgXHA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
