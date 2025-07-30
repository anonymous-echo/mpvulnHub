#  edusrc证书站漏洞挖掘(垂直越权)   
PWN师傅  PwnPigPig   2024-03-24 10:58  
  
点击「蓝色」字体关注我们！  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1QOhjH6BG8icNiaqNn5y0XVL9rnsN0QEO8TrhWyQcpe9tf8PRC3BAaYiaqQ5PAKVrjm4iatIFACP4ZZw/640?wx_fmt=svg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1QOhjH6BG8icNNpYJ1YmEicqDnOQdk428NRpKWLFFCNIWVBg3SibGKYJiaFxfoGSyibOwMLpUwL5gkKKa/640?wx_fmt=svg&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8ql0AibqlYTZQNreDb6UTYaNBvTLJ1h6N2LfLOH0O8HfvDb2YyZ3EvnZr8FfU4EH0L2QBz6g1FPSicA/640?wx_fmt=png&from=appmsg "")  
  
一眼定睛  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8ql0AibqlYTZQNreDb6UTYaNzjI9c3QUYSkvs1HNzaM8TRxoS3LUGz91E0J5ljxAdicqqnbYBC0U2QA/640?wx_fmt=png&from=appmsg "")  
  
来到该小程序  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8ql0AibqlYTZQNreDb6UTYaNZ62w8ZgY1WoHpXdDYVHmfOxw7K6Po5j1hQ3iaQiaTnSM6ZbDrVkBRwhA/640?wx_fmt=png&from=appmsg "")  
  
使用统一身份认证登录后  
  
来到如下这个位置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8ql0AibqlYTZQNreDb6UTYaNBcz2tkLBdicNKVPg4C0LSnibUSpL3wNqoavGaVyqoXibgYPZricfZCdx1Q/640?wx_fmt=png&from=appmsg "")  
  
今日排班接口处泄露uid  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8ql0AibqlYTZQNreDb6UTYaN42r7zicj67P40ib2y3FvTNX9uicbc93k5P3icicqAWhG6UfcqnicgoXqibkMw/640?wx_fmt=jpeg&from=appmsg "")  
  
小程序所有鉴权都是靠 uid 鉴权的  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8ql0AibqlYTZQNreDb6UTYaNS7XibJT99ticJgqVP8Vs4eY3bI531gUhfbBSibsibU7aOLGicofJRoxboGA/640?wx_fmt=jpeg&from=appmsg "")  
  
借助泄露的uid值  
  
我们重新回到统一登录进行登录  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8ql0AibqlYTZQNreDb6UTYaN4hUa8SYFP0dSD67NRyGFdUL8CKGCP2KwzXAsUkic7Y4I7jVPqLnOrCg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8ql0AibqlYTZQNreDb6UTYaNJWnq90XXnl816rXibWLZicl7JFLNTOnPzxYwNw3BOe5T6f53JmZ55TxQ/640?wx_fmt=jpeg&from=appmsg "")  
  
抓取响应包改为如下:  
```
{"data":{"uid":"4d1cda65a7ce00000000000000005***(打码)","email":"","mobilePhon e":"","qq":"","sex":"","realname":"黄智霖","username":"2111906121","rolecode":"admin","position":null,"personnel_natu re":"none_user","avatarUrl":null,"company_id":null,"departname":"","schools":[], "loginStatue":null},"errCode":"200","errMessage":"ok"}
```  
  
放包后进入,功能点全部可用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8ql0AibqlYTZQNreDb6UTYaN1D8bvqTEicKbw4y0WSCCc7icXQ6pKtzvia3sF4SkNYY33iayQupYpYZbAg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8ql0AibqlYTZQNreDb6UTYaNSiaL1WUKEw1xV139TfYkDvgDOMyssLHcyuPpZR7hiaje278Pr6ficPGeg/640?wx_fmt=png&from=appmsg "")  
  
成功垂直越权获得管理员权限  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1QOhjH6BG8icNiaibZMM3cGc4D0iaj74pjF9NoAtWRKibeBJeJj2CqGY7pWFygT18ic8ZuUschBylpho3G/640?wx_fmt=svg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1QOhjH6BG8icNopuribh1PX7Moia2XoQsVPP7uttLofM2m7hLkTp8cHchiauYSceNibf0TicgFwhQnVxpq/640?wx_fmt=svg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1QOhjH6BG8icN3vCF9WbISlpvoKsNW8VScqZQwLREQQicyxST9O4wicia9c37libdBNib781A0JT4hesIH/640?wx_fmt=svg&from=appmsg "")  
  
# PwnPigPig知识星球(限时优惠劵)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8ox5mBJTpV7nJAvcKqLKCOGOUXLUicLSoEnnCKtOm7pofQ1zbhejJfevQv1m2RhTsyJSPvqJTdRfWw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/mia12sBTzp8ox5mBJTpV7nJAvcKqLKCOGJibicFlD1iafDhI5Doh6e2DxDVc7RUfE5T5yo4HG0Eb5YyIPX62aF4zEg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1QOhjH6BG8icNopuribh1PX7Moia2XoQsVPP7uttLofM2m7hLkTp8cHchiauYSceNibf0TicgFwhQnVxpq/640?wx_fmt=svg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1QOhjH6BG8icN3vCF9WbISlpvoKsNW8VScqZQwLREQQicyxST9O4wicia9c37libdBNib781A0JT4hesIH/640?wx_fmt=svg&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mia12sBTzp8pjGeEvoRBrjia1u1n2tNBdFKreGg9kvHtK25ibfS1xcTb9GdltyINv0nkxPOAggUO2c9sYAY4DrPiaA/640?wx_fmt=png&from=appmsg "分隔线")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1QOhjH6BG8icNq8ltqdkL0Etj8twRpReKV72CV59L8pWIjUsRDfzFPrZBnSVX7Klr6a0r50k0YwzW/640?wx_fmt=svg&from=appmsg "")  
  
# # 往期推荐 #  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1QOhjH6BG8icNnOp8Wc5IAp9KmsUwUibaticnOLHrlib8h3v7Fn4icXic4EECIgldxH3iaBJg49icvjX2aiao/640?wx_fmt=svg&from=appmsg "")  
  
  
[edusrc小程序漏洞挖掘思路(越权+逻辑)](http://mp.weixin.qq.com/s?__biz=MzkyNDI2NjQzNg==&mid=2247492869&idx=1&sn=e17f6a4a21b878474dbc4fe4e72fc2fc&chksm=c1dadfaef6ad56b8d7dafeeed18c950e38364ae536d34cb0add823cea3c96a74abc5952b7ed7&scene=21#wechat_redirect)  
  
  
[一次配合任意密码重置逻辑+越权的组合拳打法](http://mp.weixin.qq.com/s?__biz=MzkyNDI2NjQzNg==&mid=2247492732&idx=1&sn=786a579c09174c9b899d7dbbb6e46d31&chksm=c1daded7f6ad57c1ccda8fd9969abdf821e65a632c8f022d1229d5c9bd301c23220d79c6b314&scene=21#wechat_redirect)  
  
  
[cnvd通用型漏洞挖掘思路-从逻辑漏洞到拒绝服务漏洞](http://mp.weixin.qq.com/s?__biz=MzkyNDI2NjQzNg==&mid=2247492239&idx=1&sn=ea393ca4bb77a3350710a4efc1f94eb5&chksm=c1dad824f6ad5132cb9cb70d449ec96039edf3f642a120e662f77c3141810c471acf9a1511c3&scene=21#wechat_redirect)  
  
  
  
###### PwnPigPig交流群  
  
  
交流群人数已满,加我微信号PWNCat拉入  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/UsichrXlnR9L0nuGUVpuV1QOhjH6BG8icNLEHo7TqicEWukegAoYd9XPtb7qxjeJYflc4JDB4ojibibTLibNYdf443FFCYxz5dt2VR/640?wx_fmt=svg&from=appmsg "")  
  
~  
  
