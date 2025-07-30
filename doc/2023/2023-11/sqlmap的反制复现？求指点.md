#  sqlmap的反制复现？求指点   
原创 MicroPest  MicroPest   2023-11-26 10:47  
  
有人问：写东西咋这么快？因为我碰到的问题不会的多啊，且乐于分享。但可惜的是读书少，无法明白更多的道理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2hnvgPYNzpLlVUibrQBia9uf6cUjhgPgKKh96rJpFRYNsvg17953by2IbmrL5mD3AnWia2fGMNGwOaEhP07jsGWgg/640?wx_fmt=png&from=appmsg "")  
  
“喜忧参半的才是人生”，这话太经典，一时高兴一时悲伤，常伴身边，董老师提炼的，这可能就是读书的力量吧。  
  
郭老师描述给“好学生”“差学生”讲课的情景，非常得经典，非常得形象和有意思。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2hnvgPYNzpLlVUibrQBia9uf6cUjhgPgKKoxhID33PKbdcLLxbjViaWSiaYaz88QN2ibJKcAVCBNbAmwgXtWyWdjZbA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2hnvgPYNzpLlVUibrQBia9uf6cUjhgPgKKHXGkhkeoB5icpxqNR38fr2bZSTkglic3PO6D87oNax3rBLW55fk82Asg/640?wx_fmt=png&from=appmsg "")  
  
  
“线性代数”，这是每个理科生都要学习的课程，听了国科大老师的网课才知道原来正确的翻译应该是“线的代数”，是研究线的代数，而不是研究几何的，原因据说是当年那个人看不懂内容就直译了。反正我当年是云里雾里的，也不知道跟这有没有关系。  
  
=================  
  
进入正题，以下是个关于sqlmap的问题，没明白，求解来着。  
  
先来复习一下，都忘光了。  
  
  
**一、基础命令**  
  
1）  
列出有关现有数据库的信息  
  
–dbs 列出所有可用的数据库。  
  
python sqlmap.py -u http://testphp.vulnweb.com/artists.php?artist=1 --dbs  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2hnvgPYNzpLHMJs0Wvl8hF0QrZXkNaQSbU24VgUpjanOae4bTCoEU7M7PyJqh0kgR3BEULbPvKbk6Nrf0iaAwUg/640?wx_fmt=png&from=appmsg "")  
  
2)  
列出有关特定数据库中存在的表的信息  
  
现在使用 -D 指定我们希望访问的数据库的名称，一旦我们有权访问数据库，我们就会想看看我们是否可以访问这些表。为此，我们使用 –tables 查询。在本例中，数据库名称为   
acuart。  
  
python sqlmap.py -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart --tables  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2hnvgPYNzpLHMJs0Wvl8hF0QrZXkNaQSoiaxoeibuWGrRT4ZzxTpZwgakbOicH8hvG6aKMmoKINMRngqfWnCwmtJg/640?wx_fmt=png&from=appmsg "")  
  
3)  
列出有关特定表的列的信息  
  
要查看特定表的列，我们可以使用以下命令，其中我们使用 -T 指定表名，并使用 –columns 查询列名。我们将尝试访问表“users”。  
  
python sqlmap.py -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart -T users -columns  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2hnvgPYNzpLHMJs0Wvl8hF0QrZXkNaQS8S7R8f3o5QLWvB7Q91GH0hZo9EOTnSznhdDYrUvkqn1MMjia05ch0rg/640?wx_fmt=png&from=appmsg "")  
  
4)  
转储列中的数据  
  
我们可以逐列转储列的数据，也可以将“用户”表中存在的列全部转储.  
  
python sqlmap.py -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart -T users -C uname --dump  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2hnvgPYNzpLHMJs0Wvl8hF0QrZXkNaQSuPybxOts2PZWkpT4edbe5jNqMTjIoe4FRCbdyFCf2nryqMVkibq2BkA/640?wx_fmt=png&from=appmsg "")  
  
python sqlmap.py -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart -T users -C uname --dump all  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2hnvgPYNzpLHMJs0Wvl8hF0QrZXkNaQS56uZxA8cDshjntOOWIKmyHJXKHhNfYb6PnGWVftVF0YBZ4O5X0xWmA/640?wx_fmt=png&from=appmsg "")  
  
  
**二、sqlmap速查表**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2hnvgPYNzpLHMJs0Wvl8hF0QrZXkNaQSVWialNoOjFUdT0CdiczqQD1cVbGSCMuiartMic6RjjrwM8WviaU2ichPzDdA/640?wx_fmt=png&from=appmsg "")  
  
**三、求解sqlmap的反制Rce？**  
  
作者的原文在这里《[可恶！没想到sqlmap也背叛了脚本小子](http://mp.weixin.qq.com/s?__biz=Mzg5MDY1NTg3OQ==&mid=2247485138&idx=1&sn=a23a864e54adcc526054c8cbf4a29919&chksm=cfd8033af8af8a2cb0eb796062fb77dc6edd4a1b8c67dd3140ea78150190468e66f0741fdd5a&scene=21#wechat_redirect)  
》。  
  
大致意思就是构造一个  
蜜罐，他人在sql注入时触发反制，反控对方。  
  
具体  
方法看作者的那篇文章  
，  
是21年的一个漏洞，  
结果如下图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2hnvgPYNzpLHMJs0Wvl8hF0QrZXkNaQSwAeZ9413JvorVEUuPxI7E5dqnsWibQmg4NROMZRWhfiaOVTDjLT2o89g/640?wx_fmt=png&from=appmsg "")  
  
我按照作者的思路进行了复现，但没有实现，无论是现在的版本还是以前的版本。  
  
现在发出来，请大家参与研究下，并指点我一下。  
  
  
  
  
