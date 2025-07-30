#  SRC实战篇-还在交Druid的低危漏洞？   
原创 lvwv1  OneTS安全团队   2025-06-03 07:00  
  
**声明**  
  
  
  
  
  
  
  
  
本文属于OneTS安全团队成员lvwv1  
的原创文章，转载请声明出处！本文章仅用于学习交流使用，因利用此文信息而造成的任何直接或间接的后果及损失，均由使用者本人负责，OneTS安全团队及文章作者不为此承担任何责任。  
  
使用ARL-plus框框一顿扫得到资产  
  
http://IP:48080/login.jsp  
  
访问站点后：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DLp52FBQiacO46ib8PtxDsXWt569e9H1FENcoMibs7GYfy5AXC5zicT1F1jicnoW9THqicSJ2VZNHs7Lyw/640?wx_fmt=png "")  
  
  
随手访问一下/druid/目录，朴实无华弱口令druid/druid进来了  
  
翻翻URI监控，看看这个服务器有哪些接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DLp52FBQiacO46ib8PtxDsXWet6wtzj8GqqHhtQadyT176lLxIKRia9xHMEWgjEAFySTATD9bFRibGjA/640?wx_fmt=png "")  
  
可以看到一堆session，其中包含访问地址为本地地址的管理员session。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DLp52FBQiacO46ib8PtxDsXWKIcwibicV0WYXr7cZ464kg41sibZJBJy5wJ69x6DVqmd1r1YRIscnSwPQ/640?wx_fmt=png "")  
  
那就构造请求，获取到了数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DLp52FBQiacO46ib8PtxDsXWXPdFg4bPlYtjdk6YoHL01eWJo3GrCB3GN417Gn1XiavsxrWJGicTwJRQ/640?wx_fmt=png "")  
  
继续寻找有价值的接口，使用findsomething  
  
  
简单构造：  
  
http://IP:48080/search/CommonCustSearch.jsp?SearchFormName=CustomerAddToBrokerForm&needdataview=0&SearchType=fundbroker&EditElementName=Showbrokeraccount  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DLp52FBQiacO46ib8PtxDsXWicq8JeMIEg4aictEkyc9Kxs0ovyx2Q4BGOc1Wu5icnibiaWdBu42W2j609A/640?wx_fmt=png "")  
  
没有可以R的位置，后台随便翻翻，后台系统账号，企业组织架构人员信息均有，高危没跑了，收工  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kJjVGsbcK2DLp52FBQiacO46ib8PtxDsXW9oYWiasib85R0UdxwOoqxNiatGJmvZIfjS22Kiaic4TdywkeoDGeEnKHQDg/640?wx_fmt=png "")  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
