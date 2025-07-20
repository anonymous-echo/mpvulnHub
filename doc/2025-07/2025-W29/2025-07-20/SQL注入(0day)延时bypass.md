> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMjQ0MTk1OQ==&mid=2247484131&idx=1&sn=0606b9a86fd8c899d2034812d3b44c1b

#  SQL注入(0day)||"延时"bypass  
原创 n  jacky安全   2025-07-20 00:00  
  
                      
    在网络安全的世界里，SQL注入永远是那个既经典又“无敌”的漏洞之王。无论是绕WAF、过防火墙，还是靠一条精心构造的Payload 直捣数据库核心，搞渗透就像用杜  
lei斯  
延时——讲究的就是一个“持久战”。耐心构造语句，层层绕过限制，把数据库的每一个字段都“填满”，直到它乖乖吐出管理员密码。而今天，占用n师傅的贤者时间给小破站来个“大调查”，手把手教你如何用最骚的Payload，打穿最硬的防御。准备好了吗？这场关于SQL注入的“持久战”，现在开始！  
  
开幕雷击，六个大字  
“注入点有过滤”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe93o6F8XZc4Nps0IsnJjT2oz3QwyH3jg4IppEUTMobMCCqbW71JvTvfTQ/640?wx_fmt=png&from=appmsg "")  
  
不是哥们，我请问呢？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe93KsHNhvM07nt1vbHVHibgkAjJwSD8rzlmJcMdyoGGq8juenicDeWB25gg/640?wx_fmt=jpeg&from=appmsg "")  
  
看看内搭，数据包发来：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe939mKs6HsCFUIAyJwiaCicEaLiatpjS1bicdCQ2gwR1aiacOQjW0XWsOibxOmQ/640?wx_fmt=png&from=appmsg "")  
  
请求包是这个屌样👇  
👇  
👇  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe93sXsjdicaXpPwTXvTibg5su3ax7MeTbufibhIgGma3pljzbmmPmvic1uuFA/640?wx_fmt=jpeg&from=appmsg "")  
  
没看懂好兄弟表达的意思，“不懂?”手艺人直接上无敌payload填满数  
🥵  
据  
🥵  
库  
在高速  
鼓掌  
👐下  
响应包也是成功达到高chao  
👇  
👇  
👇  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe939odPoW9LITEsJudibJhqZUkVqGHWZU1ncgLJO12oc88icW33hqbYPkmw/640?wx_fmt=png&from=appmsg "")  
### 打完收工，n师傅刚准备打开某角社区，好兄弟又来打断施法，延迟贤者时间  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe93gUcNnrUnkXfSFrljBGg9vqwkxvoO0uTeb8ST8CXmn4t61Nvziatl7Ew/640?wx_fmt=png&from=appmsg "")  
### waf ？？？  
###               
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe93ibMyPNvbmRu9HdEKVX0auicB4ibC8x2xpjDWwbFUA2JibNg6lZaJsUPNGA/640?wx_fmt=png&from=appmsg "")  
### 有点生活常识的xdm都知道吴涛才是真的爽，第一步先拖裤子  
### 看一下原始屌包👇👇👇  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe93uibYIOgs9G1OcgJYKamo0co28v8IjLsOyDYOJL4icTdAtlq1cJqtsvfw/640?wx_fmt=png&from=appmsg "")  
### 单一参数是吧，n师傅摸索到这个注入的G点打出加大加长狼牙*payload直接狠狠控制，调教后的请求和响应👇👇👇  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe93zF0IrEibjlKiaMicZiaodHcA9SiaauItD1p1py19eQLHnYsKQMSNqAFZ4nQ/640?wx_fmt=png&from=appmsg "")  
### 由于使用了杜lei斯延时，好兄弟又又又™️打断n师傅施法，并请教有关“延时“的技巧🥵🥵🥵（这里说明一下，后端是pg的库）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe93VqI7pBpyBcib1mxowSDNQviaTpAK7IDhkPUibBmqMEoV38fEt9BJSDfJw/640?wx_fmt=png&from=appmsg "")  
### 此时的n师傅👇👇👇  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe93frLZhj7xbPiacympo5fNdHiaj1ELVhkwd1spO3xnJBRzrp2ia2rNZ9xVg/640?wx_fmt=png&from=appmsg "")  
  
有的兄弟有的有的  
  
快进⏩X8  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe93weia6Ir13yxoJcMib7aDRVwBfog6Dx3sUCSNcbv4BicAia3NciaJib5S6YIA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe93meKAz2LLoFtTkdNWY3RFibtqSOjqFSJXMDDmJxryfSsgjI7BfJhkiapA/640?wx_fmt=png&from=appmsg "")  
  
延时成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZR1w6JVBWe2mdqSibUqfyeWvGPibrTe93hVzgKSeGQcgmjI3FCIOkvl6T5Q3Do4iceARHCTUyM0mwLNjhgL2AiczQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
