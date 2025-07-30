#  黑产团伙正在利用 ES 未授权访问漏洞实施勒索   
原创 myh0st  信安之路   2022-08-12 09:45  
  
最近在测试 Elasticsearch 的未授权访问的问题，其本身是一个文档型数据库，如果存在未授权访问的问题，那么就一定存在数据泄漏的风险，如果无任何有效数据，那么也可能被用来存储违法违规的内容，同样可以给企业带来麻烦。  
  
就在昨天，一个知名企业内网被勒索病毒侵袭，造成大面积系统无法正常使用，这给企业带来的损失是不可估量的，今天我发现了一些针对 Elasticsearch 的勒索方式，以下是其留下的勒索话术：  
```
All indexs has been dropped. But we backup all indexs. The only method of recoveribing database is to pay 0.021 BTC. Transfer to this BTC address 14UCEfQG5vs7kZAbFrcZ7K4BCiEa48mdFu . You can buy bitcoin here, does not take much time to buy https://localbitcoins.com or https://buy.moonpay.io/ . After paying write to me in the mail with your DB IP: recmydata@onionmail.org and you will receive a link to download your database dump.\n
```  
  
大概意思是说：  
> es 的所有索引都被删除了，但是黑客团伙已经备份了所有数据，如果你想恢复这些数据，需要支付 0.021 比特币。  
  
  
说是这么说，我认为，大概率支付后也无法恢复数据，这种批量勒索的方式，估计黑客团伙也没有办法把所有数据备份，这种就像大海捞针，坑一个算一个，所以建议各家企业自查自家使用的 Elasticsearch 是否存在公网可以访问并且存在未授权访问问题的系统。  
  
整体测试下来发现 676 个未授权系统中，有 436 个被该组织发布了勒索信息，勒索比例为 64.5%，这个比例还是蛮高的，这些目标的发现大概率是通过网络空间搜索引擎，通过搜索端口 9200 开放的目标，批量检测并添加勒索信息。  
  
下面以其中一个例子来看看该黑客团伙留下的信息，首先通过访问路径 /_cat/indices  
 查看所有索引信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfdBkY4lrsWJ3tS6iaV2doR0lW0OnrjiaQZPx6xicUB3v3Unibtw3NIRS1WNeWm1pA5LTAoqh5BaFq5PpQ/640?wx_fmt=png "")  
  
图中索引 read_me 就是黑客团队创建的一个索引，用来提醒企业进行勒索，编写一个简易 python 脚本来获取一下这个索引的内容：  
```
```  
  
获取的信息如图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sGfPWsuKAfdBkY4lrsWJ3tS6iaV2doR0lXRpZ3Che2UoibaCaibibz2IgttbBib8Uy1T7E8m9QXMqAxia447B4IAqH6g/640?wx_fmt=png "")  
  
上图就是该黑客团伙留下的勒索信息。  
  
最后再提醒所有企业，做好边界防护，在信息安全方面增加点预算，最起码要招一两个信息安全专业人才，比没有强太多，像这类事件就可以轻松防御。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sGfPWsuKAfctHSYBwchiaKgp7icmkPcUuXLoXw2e0x1LRxK2jcOvnAAExok3ricOFogCLqAXicAOhQYgzy4bmEkOfw/640?wx_fmt=jpeg "")  
  
