#  基于DeepSeek AI 代码审计漏洞 v1.0上线！可本地ollama调用 | 工具   
秋风  渗透安全团队   2025-02-05 02:42  
  
### 前言  
  
经过相当的一段时间开发和很多通宵的优化修改，内测，这个工具总算可以把1.0版本拿出来给大家了，同时非常感谢lingview师傅让开发得以顺利，zac(点点)师傅给出了idea，并参与到优化中，非常感谢  
### 工具亮点  
  
结合了污点分析+ast分析+AI分析(两轮不同提示词校验)验证并输出payload  
  
拥有在线和离线两种模式 api调用和本地ollama调用  
  
支持php和java的审计  
  
以及看起来还不错的功能优化调教  
### 工具截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibdxaL75td0foA4FJLW3CA7Sf30vNLKBAbuVkX6kR9NiamibtUuiahPzXPibcIgQ7DGC1Fm90icobzeWfeauRuRAAb9A/640?wx_fmt=png&from=appmsg&random=0.6694540883544464 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibdxaL75td0foA4FJLW3CA7Sf30vNLKBAiaib6ibyicNW7AnHhxKgbyXIuRIkQuUnicsg256qjXjqAE6oRfFe609Jib1g/640?wx_fmt=png&from=appmsg&random=0.2054542768858767 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibdxaL75td0foA4FJLW3CA7Sf30vNLKBAsl7OTjEPkkibn3EccUb9esbpBXQibozUMyPtAc9dD4zkpSOI6OlIS4HA/640?wx_fmt=png&from=appmsg&random=0.16001185358475922 "")  
### 使用手册  
  
左上角文件 打开文件将会导入文件夹并自动开始审计  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibdxaL75td0foA4FJLW3CA7Sf30vNLKBArY80GxcOPdzUboUXeKOib5tM1Gtud4KlxhFAy4KIAoJnRxuCoKE3R4w/640?wx_fmt=png&from=appmsg&random=0.8369872319361351 "")  
  
在第三页的设置栏我们可以选择在线或者离线模式  
  
在线模式的API key 和url我们比方使用deepseek https://platform.deepseek.com/api_keys 在开放平台创建key即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibdxaL75td0foA4FJLW3CA7Sf30vNLKBArCjwcQYGLLCyacUOenVcIlHzroyxf5ia1zCloZv7pNGLgpM8uYrl74Q/640?wx_fmt=png&from=appmsg&random=0.5763872178433849 "")  
  
离线模式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibdxaL75td0foA4FJLW3CA7Sf30vNLKBAZBPqBlqgfvOPlFIVzPxD1YRspErahYh0QBPJfXDkEdhiaIj4wJVQ7OA/640?wx_fmt=png&from=appmsg&random=0.09678070109733872 "")  
  
离线模式仅支持ollama 内部写的也是ollama的调用 模型名称是你的ollama list的模型  
  
离线模式提示词可以修改 不过这会间接导致很多问题，包括但不限于 无法正常回显 误报率增加 等等问题 不过改好了的话将会使误报率大大降低 这个是我们提供的 提示词模版:  
```
你是一个代码审计专家用来辅助我判断代码有没有安全漏洞，你的职责是判断我给你的漏洞有没有可控点，我只会给你代码你只需要回答，存在漏洞，不存在漏洞，以及无法判断，不需要解释！！！，不需要你给出修复 防止 等等建议只需要回答，存在漏洞，不存在漏洞，以及无法判断这几个选择 总之回答的 存在漏洞，不存在漏洞，以及无法判断 不需要解释是核心
```  
  
  
离线模式我们不进行二次校验，并且不推荐和建议大家去进行大项目的离线审计，只建议单代码文件,或者较小体量进行审计，这完全是因为本地大模型GPU的局限性，此外，我们有完全离线模式就是不使用ai 纯污点分析用于快速检索排查  
  
漏洞跳转到代码界面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibdxaL75td0foA4FJLW3CA7Sf30vNLKBAMX8Pq8ZdrLpI5gI0VicwMicVDLUTUWsnIOyiblCjEr0Lm3jiaSJ3pc3FSw/640?wx_fmt=png&from=appmsg&random=0.980994157687129 "")  
  
点击漏洞即可跳转  
  
这个搜索是文件内搜索  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibdxaL75td0foA4FJLW3CA7Sf30vNLKBAFvQfKG8sXaCHGcerTPxjcjEvUeDHJlwMxlDiacxPG7fia54B6wybe0bw/640?wx_fmt=png&from=appmsg&random=0.022772538564668876 "")  
  
在左上角文件-->搜索是全局关键字搜索  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibdxaL75td0foA4FJLW3CA7Sf30vNLKBA5pnAwq3jKQTVm6fOQ1W9tEMC6QtOicTquxfiaFS0KkwnNZiav3uQZZJLw/640?wx_fmt=png&from=appmsg&random=0.04188739709090128 "")  
### 获取方式  
  
蓝奏云:https://wwcl.lanzn.com/icRyV2lkqflg  
  
同时希望大家可以在群里反馈 让我更好的去优化这个工具  
  
## 群-聊  
  
下方二维码添加好友，回复关键词  
**秋风代码审计**  
进群  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DJQJHqbNuibGkowiagnQA6ia24yM42ia93iaZfQL8Nd4jVMVdvWmaoNbw5KdfKdicjy8uDEydN2YUCQ2tg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AOzYX7kxefGbGGZg3g1ltkN30q9hceg23PiczgUqMT0EE9w0fLK9uw1eKWwQX9TljXQe1OQeHRZ2Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
