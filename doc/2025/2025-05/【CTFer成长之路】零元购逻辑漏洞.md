#  【CTFer成长之路】零元购逻辑漏洞   
原创 儒道易行  儒道易行   2025-05-11 12:00  
  
## 逻辑漏洞CTF  
  
访问url:  
```
http://1b43ac78-61f7-4b3c-9ab7-d7e131e7da80.node3.buuoj.cn/

```  
  
登录页面用随意用户名+密码登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwVwibdmdUkaoLf2icEfm7l9r8hdibqIYtM46aElMHNEUvw5aAbYTHFw4lXiaULvnnHKnyoMq84VJ03Ew/640?wx_fmt=png&from=appmsg "")  
  
访问url文件路径：  
```
http://1b43ac78-61f7-4b3c-9ab7-d7e131e7da80.node3.buuoj.cn/user.php

```  
  
登陆后有商品列表，共三个商品,点击购买flag  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwVwibdmdUkaoLf2icEfm7l9r29jdbEcPSFN0JRj1YCocSn5aXVWXI4cZp50RCTNUeNibBlC2Sau05YA/640?wx_fmt=png&from=appmsg "")  
  
钱不够  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwVwibdmdUkaoLf2icEfm7l9ribflqXjVbSQj3VjO9uqLRwCmMsrt6dbJjKpDzK1OQyst53jauGzicSww/640?wx_fmt=png&from=appmsg "")  
  
另两个商品购买会显示各自对应的内容，并在多次购买后也会提示  
```
Money Not Enough

```  
  
结合对应的金额不难发现存在初始金额，并且金额有限。在进行购买时，url形如：  
```
buy.php?cost=200&goods=2

```  
  
其中便有消费金额的参数，后端根据消费金额直接对余额进行增减将消费金额修改为负数时，便能够使余额增长：  
```
buy.php?cost=-200&goods=2

```  
  
将数字调大便可使余额能购买Flag：  
  
构造payload：  
```
buy.php?cost=-20000&goods=1

```  
  
此时便能够正常购买Flag  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwVwibdmdUkaoLf2icEfm7l9rcParrlzgmgceBlrysK03ZJUCG4xJwcHJzcicvCD9icIhUqv9TW88Pruw/640?wx_fmt=png&from=appmsg "")  
## 声明  
  
文笔生疏，措辞浅薄，望各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  
