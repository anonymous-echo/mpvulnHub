#  SRC案例 | 某公司小程序四个漏洞挖掘过程   
原创 lyc  Timeline Sec   2024-02-23 18:33  
  
## 前言  
  
好不容易才抽点时间学习一下渗透，补天公益SRC上随手找了一家公司练手。因为公益SRC很多时候拼手速和资产收集，所以这次直接瞄准小程序开搞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4ricnicB3C7hx8DjvXqF5ftNBed1jAOMxzBHyhFz5xGZDwbbm11rD6I0Q/640?wx_fmt=png&from=appmsg "")  
## 漏洞一：逻辑漏洞  
  
找到第一个小程序  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4yoyRUjoicwtO3ic6rQFJkn84tw6cibgUsPcaPeZJE8gV54wHicmTR7NIoA/640?wx_fmt=png&from=appmsg "")  
  
然后微信登陆此小程序  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4QoMDFaybzEQIh3ysuUeazo44VfYDAqIkicY72lCozOYpe6OiaibgGFL1Q/640?wx_fmt=png&from=appmsg "")  
  
接着在”首页“点击”签收凭证“，抓取此数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4QDupwITCxzQnKbPtHZAEZCe8pdPxBb2icFt2UdTvDkGgNjpRerkRqLw/640?wx_fmt=png&from=appmsg "")  
  
数据包如下图，将此数据包里面的”phone“和”mobilePhone“变成空值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4wAFS1BhGL1Lx6XdPjZPwHY2CSbOuU8eyMVc7hb8QsgxQDQrUicvRNnQ/640?wx_fmt=png&from=appmsg "")  
  
发现存在有信息泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4xiaECOBqT0vRONIchjgwAqJ3Iic1VlUhxNOplGaufNMYfv4f3mR0NeRQ/640?wx_fmt=png&from=appmsg "")  
  
放到web端的页面更方便，发现有订单信息，访问里面的参数"fileUrlList"的url  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4KL9SP6cfazwiaDFfzCrKtg8pbTrpe54UIfadan2fiawSVs3cpWdF0tDw/640?wx_fmt=png&from=appmsg "")  
  
发现全是签收订单，手机号，姓名等敏感信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4QAnWohsE1m7jNbAMDsqNLux3TibYqogVjhkOtgia4jfxc0kqWEFHgKVg/640?wx_fmt=png&from=appmsg "")  
## 漏洞二：前端绕过登陆后台  
  
找到第二个小程序  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4Q19qMbQgJya7JLaewxcOGyl8LYicIEPlfctO8pKzoZ1c0CPLr6vibSQA/640?wx_fmt=png&from=appmsg "")  
  
点击进入，是一个登陆界面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4wiaHv4ZibS3WZ8yWYck5GYaiblXVDYTia0RKykpxuPDOVwe91qFojmbhQg/640?wx_fmt=png&from=appmsg "")  
  
选择账号密码登陆，随便输入一个账号密码并抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4jIORljXd5T0rbH3Qnzx8JicicZktdsOAmKT83E05qXyKghBV0Mun0E8w/640?wx_fmt=png&from=appmsg "")  
  
拦截响应包，将"code"修改为0，两个false修改为true  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy43Wq4hhVdd7AqlytHhmNukvYcia2gCCfic1TiawLOsQXFiauLyNwLAJuT5g/640?wx_fmt=png&from=appmsg "")  
  
修改之后，成功登陆  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4KJr76Cq5WqibdJWROT60QQoCocGKTquOoymjfCTbicc5fib5KXfW5uAGw/640?wx_fmt=png&from=appmsg "")  
  
修改之后，成功登陆直接进入到工作台，但是因为未授权访问，只能拿到数据，没有办法进一步操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4d17Q7YE0uIibXozg6ibTKCGiaacEOX7R1W9kib1vQJgmQRL4gT3Wd1Fh8w/640?wx_fmt=png&from=appmsg "")  
## 漏洞三：越权漏洞  
  
找到第三个小程序：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy46mc2CXTJhPqYEInPTmzVK7IBGKjbIIQIwLNC6nTbAShj4I63gSg9MA/640?wx_fmt=png&from=appmsg "")  
  
进入后注册账号，在个人设置中心找到收货地址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4GWLnrqHRmCCJZiaPHOBHOE4xQ1UmmzMOYooNhbEibA8LhDfuHBRJ4nSQ/640?wx_fmt=png&from=appmsg "")  
  
进入后注册账号，在个人设置中心找到收货地址抓取收获地址的数据包，发现存在member_id  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4uhuPC3yxE4zanSzIAM0EWVT1Fdx4BQKrHQX36QxOzcvbSQQXtHSia0Q/640?wx_fmt=png&from=appmsg "")  
  
因为我没有写地址，所以响应包中没有数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4BLhxqYnAoqtm7u2rclYY4U7xLg7iauEr34kpnu7aNozPDVicatOl99hA/640?wx_fmt=png&from=appmsg "")  
  
修改一下member_id的值，发现越权成功，可以看到别人的姓名、手机号、地址等等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy42fhd5oyUxvXPEjB4ZjjOxD6poQQFzSxf5dKZoNKSZicxS7PjoOrWMtQ/640?wx_fmt=png&from=appmsg "")  
## 漏洞四：信息泄露  
  
第四个小程序：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4TImcpRxUxehNTsmjDMwOGUmIuntOWL4d6qJSc6YaXKZULfcINNxfhg/640?wx_fmt=png&from=appmsg "")  
  
这个小程序没有啥含金量，直接贴脸开大
点开这个小程序，直接抓到一个数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy4fYCUbZ6mxW980fQXlV46E2xq48S3XCMg5j46jSGDwkcbRKpibcecSqQ/640?wx_fmt=png&from=appmsg "")  
  
响应包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VfLUYJEMVsiarBGiaJfcPgFhwq8qbx3icy42MmKNzaGF7sltQ154jPDsCaOCNGtLpvo3NdtBMV3p6WsCt8QCkmIMw/640?wx_fmt=png&from=appmsg "")  
  
end  
  
  
****  
**学习更多SRC漏洞挖掘技能：**  
  
SRC学习交流QQ群：公众号后台回复  
“  
4”  
SRC知识付费帮会：公众号后台回复  
“帮会”  
了解/报名SRC培训课程：点击文末  
阅读原文  
  
  
  
