#  【安全圈】OpenAI 曝新漏洞，允许新用户“无限试用”   
 安全圈   2023-05-05 18:48  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljsJVJHhaCOeUkoze16FrNjE24yjZVib01Tl7diaq0PGm6wazJMuo3K51rsrhdiagwEDicqXQtmMQlIJQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
  
  
漏洞  
  
  
  
通过该漏洞，用户可以免费获得无限的信用额度来测试不同的OpenAI项目，包括ChatGPT。  
  
不久前，OpenAI 为了让用户尝试其他开放的人工智能项目，特意为新用户提供了免费的信用积分额度（约7美元）。随后网络安全公司Checkmarx表示，目前发现了一个漏洞，允许用户滥用试用，并在新账户上获得无限的信用积分额度。  
  
研究人员表示：通过拦截和修改OpenAI的API请求，我们发现了这一漏洞。该漏洞能够使用同一个电话号码注册任意数量的账户，获得无限的免费积分额度。  
  
为了注册试用，用户必须输入他们的电子邮件地址，点击发送到收件箱的激活链接，输入一个电话号码，然后输入短信验证码。电子邮件和电话号码都必须是唯一的，用户才能获得免费的积分额度。  
  
然而，不法分子为了让同一账户获得更多的信用积分额度。他们对电话号码进行细微的改动，例如在国家/地区代码前面添加前缀。最终，他们通过使用同一电话号码的不同前缀的变化绕过了要求。  
  
研究人员解释说：这一漏洞允许一个恶意的用户拥有多个账户，并获得更多的信用积分额度，而且用的是同一个电话号码。  
  
但这对他们来说似乎还不够，因为他们想将信用积分值提高到一个更恐怖的数额。  
  
然后，研究人员将开源工具REcollapse投入使用。这允许用户模糊输入和绕过验证等。  
  
经过一些初步测试，观察到OpenAI API对一些模式进行了清理。在某些非ASCII（美国信息交换标准代码）字节上使用Unicode编码使我们能够绕过它并注册更多帐户。  
  
目前该公司在收到通知后修复了该漏洞。  
  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliavGLlka4ryB5YcPwZDUbQeOk2HTbEldxIlI1jSbFSO9UwQAaaibqictAlMu21nrGBicO8DMgwpQwHicQ/640?wx_fmt=png "")  
[【安全圈】只要一部“诺基亚”，15秒就能偷走一辆车](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033652&idx=1&sn=797b61c94be70a0742295f127ceb2e62&chksm=f36ffe34c4187722a97beeb2d21605a276ab2fb97b4f42228590a2acbe65c11ecba4d51aa68b&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliavGLlka4ryB5YcPwZDUbQeq0aKa6eVzjIj15eoicmiaianu46Dxr1epA4MRsevou9P2iaztK3FibV9XIQ/640?wx_fmt=png "")  
[【安全圈】三星电子为何禁止AI工具？](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033607&idx=1&sn=94ed923ad31b5356baf15324f363b43a&chksm=f36ffe07c4187711262c0fc19fb8d3c22cad8dbb2e75e17ca5b80e9339ca9eedf09183c2d729&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliavGLlka4ryB5YcPwZDUbQenwqbibUKIuCN8UtaugwpO91c8KHEzd8WPmsKbPeWfxHuyVxoEkkZEXw/640?wx_fmt=png "")  
[【安全圈】百度文库接入“文心一言”，15 秒即可帮你创作一篇文档！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033526&idx=1&sn=8e7773fe007e75a24d99c4c659cabaff&chksm=f36ffdb6c41874a0e3c8d2f8fee9a1b1475aa87f5eab82ec06607f52ff67bc0e8c605a795039&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliavGLlka4ryB5YcPwZDUbQeibkKnzYctYHKOyI8UIOjicDJx2d7J5icVtP21s0FFx29YPgP94axRkmsg/640?wx_fmt=png "")  
[【安全圈】男子雇佣“黑客”恢复聊天记录，4000元换来的却是一只插座](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033652&idx=2&sn=c5b599489b78290d83ffeeb5d2a638bf&chksm=f36ffe34c4187722e8d90c9ecce2c7215efcede47f4395be2b5527625861131bc8823b6b4a77&scene=21#wechat_redirect)  
  
  
  
[【安全](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652030093&idx=4&sn=e988dc890e595695befbdb177d11b98c&chksm=f36fe8cdc41861dbd78f5270a42fca19c1d45cb375ef4469e8a36bef1f42620f990d03714872&scene=21#wechat_redirect)  
  
  
‍  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
