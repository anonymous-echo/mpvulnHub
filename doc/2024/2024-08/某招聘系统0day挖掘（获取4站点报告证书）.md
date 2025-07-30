#  某招聘系统0day挖掘（获取4站点报告证书）   
goddemon  goddemon的小屋   2024-08-24 09:21  
  
## 前言：  
  
小白文，首发在星球里面，没啥好多说的  
  
21年的挖的漏洞了漏洞均已提交且均已修复，这里文章只做技术交流  
## 挖掘过程  
  
对我来说，毕竟喜欢直接黑盒挖0day，一个0day挖到后就可以刷上百分。  
  
  
如该系统正常找了一个招聘系统用的比较多的![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC6XyHfex50PvvMoQFyvp3dWOaMM5reokD2UokuJI6hlIfVmn5PO3hrboDotxC4Xj9pvooDSaAsFdQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
如该通用系统，该通用系统存在一个注册功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC6XyHfex50PvvMoQFyvp3dW1KUIvl3obHxqmLCy6ibjHlqkvk7QnRApggbmEuzUkjTKliaiaicDKSvrNQ/640?wx_fmt=png&from=appmsg "")  
  
  
正常的进行注册一个账户进去测一测系统相关的漏洞功能   
  
  
该系统内部存在如下的功能  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC6XyHfex50PvvMoQFyvp3dWKxLYn9ysibkNhqfZhicHnxdQFJUgKnWsicWBBEDdYRbEGJlicabslnrZgw/640?wx_fmt=png&from=appmsg "")  
在进行挖掘的时候正常走burp进行抓包，然后正常功能点点点，分析请求包里面的参数接口  
  
  
获取到大量的请求包
其中这些接口引起了笔者的注意![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC6XyHfex50PvvMoQFyvp3dW3YWvLHFRh58fwYFV1ib891V1StVtBqUibDuibM12DNod868YwqP7Kbfnw/640?wx_fmt=png&from=appmsg "")  
  
  
所有的接口均由a.do?action去调用方法名以及entityId进行控制实体  
  
  
那么这里即如果我把这个方法改成其他的方法是不是意味着我可以直接有可能调用一些未授权的方法呢？  
  
  
然后尝试改成其他的果然是可行的
如改成list![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC6XyHfex50PvvMoQFyvp3dWrGqlFsp5DeHeyOHia8pcUqQajs2EBlZC1unCTm6CKWEN1icyOYcU16jQ/640?wx_fmt=png&from=appmsg "")  
那说明我只需要找到一个正常功能获取一些查询的参数然后尝试改action以及entityId即可能可以获取到其他的内容  
  
  
因此这里在系统中寻找那些参数比较多的模块，以及内容字段是由外部控制的模块，获取到了一个搜索模块。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC6XyHfex50PvvMoQFyvp3dWQSFqibzS8YWcdTkOg5a4eEwjUnI8gLPkYekmiaS8mLBKPd8pZPxkZFXQ/640?wx_fmt=png&from=appmsg "")  
该模块包为这个 即columnFieldNames是由我们传过去进行获取的，这就意味着这个传入字段是受到我们控制的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC6XyHfex50PvvMoQFyvp3dW6VkhJdU74ZufYz5ro5N52oicYSuCEY4lI9Gk98SMXdZ77QFmia7DqjDg/640?wx_fmt=png&from=appmsg "")  
但是这里的重点先不管这个，先管如果我们把entityId改成一些敏感字段到底能不能越权  
  
  
因此找到一个敏感字段名就比较重要，对于笔者而言笔者这里去进行点击修改密码，修改密码处可获取到用户的字段  
  
（因为用户更改密码或更改信息肯定是调用用户字段去更改的）
因此这里就可以获取到这个系统中危害较高的字段
然后在结合上面的接口形成完整的闭环。  
  
然后结合更改columnFieldNames字段即可获取用户的account，password等等内容，成功获取到用户的大量信息。![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC6XyHfex50PvvMoQFyvp3dW1Mw1OEV2ZgDDdIAl4fAqiaCF90Vewx9XPCUyboD63CVRqnu86HzAJbA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC6XyHfex50PvvMoQFyvp3dWw8FB6zPibnj1GlrUxONGWBqQibh45CCUajxMiamflPCBNcdnLPNvumZbA/640?wx_fmt=png&from=appmsg "")  
  
  
也成功通杀，而后正常刷屏即可![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC6XyHfex50PvvMoQFyvp3dWO9U0CZWPI0GvRHT4ic5bv3wYS6hMEDKghEoePuJMhlYqvoHlLibXC9Eg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC6XyHfex50PvvMoQFyvp3dW39wVEu4FuZxpcKhic3Yw8B0PQw807Ozg8gzJcDgp8U0fHVqXEy2q2UA/640?wx_fmt=png&from=appmsg "")  
  
  
## 思考：  
  
挖掘漏洞时，对里面的接口参数进行思考，或者会挖到不一样的东西  
  
## 最后  
  
你猜现在这个系统还有没有漏洞，那自然也是有的，自己去挖吧  
  
