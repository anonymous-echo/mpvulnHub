#  漏洞挖掘JS逆向-Burp自动化加密   
原创 Sik  长风安全   2024-02-12 23:58  
  
#### 针对Burp自动化加密的小脚本  
# Install  
```
工具mitmproxy:https://www.mitmproxy.org/
pip install mitmproxy
```  
# About  
#### 在burp中将加密字段改为明文，通过auto_encrypt.py对修改的明文字段进行加密发送给服务器，从而可以实现在burp中明文测试，避免单独加解密先复制密文再解密再复制明文再修改再加密再复制进去的繁琐，达到自动加密的效果。  
#### 该小脚本支持如下，框架简单已搭好，可轻松扩展其他更多的或自定义加密模式：  
```
mode=00 ->body全部加密,AES CBC模式,base64格式  **常用**
mode=01 ->body全部加密,AES CBC模式,十六进制格式，大写
mode=02 ->body全部加密,AES ECB模式,base64格式  **常用**
mode=03 ->body全部加密,AES ECB模式,十六进制格式，大写
mode=04 ->部分字段加密，需改正则匹配需要加密的字段，AES CBC模式,base64格式  **常用**
mode=05 ->部分字段加密，需改正则匹配需要加密的字段，AES CBC模式,十六进制格式，大写
mode=06 ->部分字段加密，需改正则匹配需要加密的字段，AES ECB模式,base64格式  **常用**
mode=07 ->部分字段加密，需改正则匹配需要加密的字段，AES ECB模式,十六进制格式，大写
```  
# Usage:  
## eg:mode=04  
  
mode=04 ->部分字段加密，需改正则匹配需要加密的字段，CBC模式,base64格式  
  
场景：json格式，对json中data进行AES、CBC模式BASE64格式加密  
  
修改代码配置，将mode设置为04  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefakBeUSdU3bBNibiaRZePEEZJGXa45bzdcPZu4rltMSW3aRjNAIIKaeZw/640?wx_fmt=png&from=appmsg "")  
  
填入AES密钥，此处由于是CBC模式，需填入key和iv  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9keferRvEcA6X9lvwiaoBNvMsHRK3bialvyjHlmibJoQPFlpNYBVn9RDt32ug/640?wx_fmt=png&from=appmsg "")  
  
修改正则，匹配你需要加密的字段，此处需修改三个地方，第一是修改正则匹配json中的data字段，第二是选择你刚修改的正则，三是替换加密后的值  
    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefPXWq3LeRFeNYibLSeAhu2dUQICR3TUegNCIibSQ4uBsqa2nsFmYX5uGw/640?wx_fmt=png&from=appmsg "")  
  
启动脚本,监听8081端口  
```
mitmdump -s auto_burp_encrypt.py --ssl-insecure --listen-port 8081 --mode socks5
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefhzWNOoHIAWCwUicd7JAzrctkVS2I2GZwJZIwic9rWBtnYE1r6WtX8lLg/640?wx_fmt=png&from=appmsg "")  
  
burp设置下游代理端口为8081  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefbQ4FDd7TEkLibX74PwXmYBbysruxH0FxTQib3CSvxngkyOtsZuoFOJUg/640?wx_fmt=png&from=appmsg "")  
  
原始数据包中data字段采用AES CBC模式BASE64格式加密  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefldEicsXPv7WE1f6ElnJia66bzcpjKNkMyg6kn03PBdwxSRdPCYDTCE5w/640?wx_fmt=png&from=appmsg "")  
  
在burp中修改数据包中data字段，  
修改为明文  
，直接发包即可，此时脚本就会自动将该字段的数据进行加密后发送，即可开始各种越权、逻辑测试，  
就免去了复制密文再解密再复制明文再修改再加密在复制进去的繁琐  
，此处样例为登录功能，那即可明文开始在intruder爆破。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefI3hKb67X3K743bQXfjicQmGf8MAibVmpzcYL02xRpRIicxBcl1GXSdeDw/640?wx_fmt=png&from=appmsg "")  
  
效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefRxXib8BWIWkDX8BIDxMJ9p4UOwxfWiaUK8ktEenaRl0yl7J5BVRthfbQ/640?wx_fmt=png&from=appmsg "")  
## eg:mode=07  
  
mode=07 ->部分字段加密，需改正则匹配需要加密的字段，AES ECB模式,十六进制格式，大写  
  
修改代码配置，将mode设置为07  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kef1n5Y8dR8zGBaN5jt3xTxjsVoFr6agUzD5GFbOQekvbtKQ2KkOJqhicQ/640?wx_fmt=png&from=appmsg "")  
  
填入AES密钥，此处由于是07模式，只需填入key  
    
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefZZ93YXvytAwyBhLpVL69NN4LgEibcZzXiaiclzia146GXOxWicX0ts9Cpmg/640?wx_fmt=png&from=appmsg "")  
  
修改正则，匹配你需要加密的字段，此处需修改三个地方，第一是  
修改正则  
，第二是  
选择你的正则  
，三是  
修改替换的关键字  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefBKAAHqAd7WfTUBpXfMemVqxmRZOIMIn7HIvticiaPOvTamibtwkAMhicPA/640?wx_fmt=png&from=appmsg "")  
  
启动脚本,监听8081端口  
```
mitmdump -s auto_burp_encrypt.py --ssl-insecure --listen-port 8081 --mode socks5
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefhzWNOoHIAWCwUicd7JAzrctkVS2I2GZwJZIwic9rWBtnYE1r6WtX8lLg/640?wx_fmt=png&from=appmsg "")  
  
burp设置下游代理端口为8081  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefbQ4FDd7TEkLibX74PwXmYBbysruxH0FxTQib3CSvxngkyOtsZuoFOJUg/640?wx_fmt=png&from=appmsg "")  
  
原始数据包中data字段采用AES ECB模式十六进制格式加密  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefQZHUbIZRqW24a8ibQqQ2TnZEFp9ibrH0IEib8Hl3GGmsLy84UBanWfXVw/640?wx_fmt=png&from=appmsg "")  
  
  
在burp中修改数据包中data字段，修  
改为明文  
，直接发包即可，此时脚本就会自动将该字段的数据进行加密后发送，即可开始各种越权、逻辑测试，  
就免去了复制密文再解密再复制明文再修改再加密在复制进去的繁琐  
，此处样例为登录功能，那即可明文开始在intruder爆破，效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefa8noZDpXyh8tH9tqtAYN4PAI3R7G1oUKTCrxAJxTDLbFR68IRWcvLA/640?wx_fmt=png&from=appmsg "")  
  
欢迎关注B站&抖音：长风安全，下次直播讲解，除目前已支持固定模式外，也可根据网站自定义模式扩展脚本自动加密方式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qIibpnAD78JfIgn6JIicVUj60sv8RQibkia9jFvlTVicXVvforFUrjZ6gkdsEGuBPZYu38hkGOW0DDibvZA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefheibA0tKpQV5q5EFdrOia90jTwf1oIafTibBCicjJPoibgdOhCia2kgGUxyw/640?wx_fmt=png&from=appmsg "")  
  
#### 推荐阅读  
- • [渗透测试完整思路及详解-信息收集第1篇](https://mp.weixin.qq.com/s?__biz=Mzg4MDkyMTE4OQ==&mid=2247483973&idx=1&sn=9b94f9ceab3f395bf7511a4828eb0b00&scene=21#wechat_redirect)  
  
  
- • [直播技术交流会](https://mp.weixin.qq.com/s?__biz=Mzg4MDkyMTE4OQ==&mid=2247483903&idx=1&sn=b72ff3f481c100db267230e4fdf2db2b&scene=21#wechat_redirect)  
  
  
欢迎关注我的公众号“**长风安全**”，原创技术文章第一时间推送。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FODKWahS5qID6ibc3bzVGj5H6PYibm9kefqRsmKWQWReluHJJd0CMgxsTiaDKLNnLI3d9e0zpPr4c6cw2iaEZhbv3Q/640?wx_fmt=png "")  
  
  
