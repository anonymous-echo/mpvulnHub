#  一次JS接口到通用信息泄露漏洞   
宓湫  UF安全团队   2024-11-22 12:22  
  
经典登入框  
  
开局熟悉经典登入框:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7ZEpqKYYgC9jwdOfXPklfoibErEoe9PVXAUYuichegs2h9WNNZ2Fr14haahvdmjwvfLuTnyz6lmEasg/640?wx_fmt=png "")  
  
常规sql，xss，万能密码，弱口令，逻辑等等尝试无果  
  
findsomething  
:打开插件看看匹配到的js接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7ZEpqKYYgC9jwdOfXPklfoibbPSsyRvicbImnfic80gEuj8zL48kdk0ZaTBApNjbkBsEXAuxNwKugnSw/640?wx_fmt=png "")  
  
  
当然这里js相关工具建议使用findsomething以及Packer-Fuzzer-master等综合利用去重在进行拼接等操作  
  
JS对抗  
  
拿到上面的js接口，先直接拼接一手，使用burp的爆破功能进行爆破一波  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7ZEpqKYYgC9jwdOfXPklfoibVqkdwViaWtRu29wRk8BJYsMCaRN5BymYdGLgXsp0MqbliavxswLAN4DQ/640?wx_fmt=png "")  
  
  
发现是没有什么结果，现在的思路就是想着从js里面在找找其他接口进行拼接或者使用一些脚本匹配js里面相关敏感信息。  
  
但是上面进行拼接的时候是直接把接口地址拼接在网站后面，例如网站为www.xxx.com 上面操作直接把接口拼接在上面为www.xxx.com/api/user 然后爆破返回404，返回404说明不存在此接口路径，如果返回401等状态码说明路径是存在但是需要鉴权，但是上面地方为404，说明路径不存在。  
  
JS拼接  
:正常来说拼接一个完整地址需要前面后端地址加后面接口 例如www.xxx.com/api/user 我们以及有后面api/user等接口，我们只需要寻找前面部分的地址，寻找方法1.js代码里面正则匹配   2.直接抓包抓取登入指向地址  获得大量地址后进行交叉爆破  
  
这里直接演示抓取登入地址，随便输入账号密码进行抓包:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7ZEpqKYYgC9jwdOfXPklfoibt8xDEsPqicvJhAwufNhn4jHKF4nBwtVcsBtz3NZq1SqjhIlxE9PFf8g/640?wx_fmt=png "")  
  
例如我们的网站为www.xxx.com 这个时候可以取www.xxx.com/api/v2/拼接接口地址 也可以为www.xxx.com/aoi/v2/ad/接口地址  这个多尝试，这个地方我直接取api/v2/然后拼接接口地址，如图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7ZEpqKYYgC9jwdOfXPklfoibuvJ50IWvw4xUYIG4YichfejRHt3PNfbgLW0T6Sl5VVVTu6LCDRVmHKQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7ZEpqKYYgC9jwdOfXPklfoibt70AITXxWxRu6BTAf9ALxtBctSibZR3rmuUCXC1KZWl3DziabIerZ80A/640?wx_fmt=png "")  
  
里面包括一些人名电话密钥等信息，未授权访问后台用户配置信息  
  
通用漏洞  
  
不知道还记得刚开始登入框最下面有一个Powered by xxx 以及这个logo 以及特定url链接  
  
这个登入验证不属于本公司，是由其他公司通用登入系统进行验证，直接上fofa批量搜索特征  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ASf2g4J3S7ZEpqKYYgC9jwdOfXPklfoib4diakxz4IFTQFhw8IZWPhicMibcLE4KpruHCI707ahpRTDW91H6ibsuKvw/640?wx_fmt=png "")  
  
其他资产直接在后面拼接上此接口地址即可访问配置信息，到通用信息泄露漏洞。  
  
JS模块  
  
常见JS模块利用  
  
1.JS接口拼接  
  使用findsomething,Packer-Fuzzer-master,jsfind等寻找接口以及后端地址进行拼接  
  
2.JS信息泄露  
    可以使用脚本进行正则匹配例如邮箱，身份证，IP，AK/SK等  
  
3.JS代码逻辑  
   可以查看js代码例如登入等逻辑进行绕过  
  
等等  
  
