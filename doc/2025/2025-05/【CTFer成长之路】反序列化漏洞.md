#  【CTFer成长之路】反序列化漏洞   
原创 儒道易行  儒道易行   2025-05-05 12:00  
  
# 反序列化漏洞  
  
1.访问url：  
  
http://91a5ef16-ff14-4e0d-a687-32bdb4f61ecf.node3.buuoj.cn/  
  
点击下载源码  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpzhBqPhhnhjo8gzTALb3vo5dey1ZjNlp7FI37wsSLoibiaeTTlsW0O8mfZuUyOuev9M6Vv9lx3rqCTw/640?wx_fmt=png&from=appmsg "")  
  
本地搭建环境并访问url：  
  
http://127.0.0.1/www/public/  
  
构造payload：  
```
```  
  
POST的参数，就是生成的反序列化字符串  
```
```  
  
进行攻击  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpzhBqPhhnhjo8gzTALb3vo5At6J6O6hLcvEs6S3ZGtBq4tjK1e3tMfZavw0g5tHSFSkWOj4RjnZMw/640?wx_fmt=png&from=appmsg "")  
  
攻击成功，页面回显如下  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpzhBqPhhnhjo8gzTALb3vo5nlxonGPApEXSrveQHzHUo3WJzyQHo55OmvjuCNFSE4VSgibZGGGibqFA/640?wx_fmt=png&from=appmsg "")  
  
访问url：  
  
http://91a5ef16-ff14-4e0d-a687-32bdb4f61ecf.node3.buuoj.cn/  
  
构造payload：  
```
```  
  
POST的参数，就是生成的反序列化字符串  
  
str=O%3A27%3A%22think%5Cprocess%5Cpipes%5CWindows%22%3A1%3A%7Bs%3A34%3A%22%00think%5Cprocess%5Cpipes%5CWindows%00files%22%3Ba%3A1%  
  
进行攻击  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpzhBqPhhnhjo8gzTALb3vo5q8Q15mibqdxvboRia4v9dHJPGia1Nopm7DQjlqhmyN5OI0zAlvgiciaxkdA/640?wx_fmt=png&from=appmsg "")  
  
攻击成功，页面回显如下，拿到flag为n1book{de70641304640057390e8fabc8b515bf}  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpzhBqPhhnhjo8gzTALb3vo5BNVGDF0jL2asgM2EzNgia8VyPtP25icVvaqtFJIG9DTgRteD2PpAibD1Q/640?wx_fmt=png&from=appmsg "")  
  
文笔生疏，措辞浅薄，望各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  
