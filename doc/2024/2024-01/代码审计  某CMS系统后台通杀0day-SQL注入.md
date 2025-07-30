#  代码审计 | 某CMS系统后台通杀0day-SQL注入   
 渗透安全团队   2024-01-03 22:27  
  
**01**  
  
  
**SQL注入审计基本思路**  
  
  
首先看下基本SQL注入漏洞原理的示例：  
```
<?php
$id=$_GET['user_id'];
try{
    $pdo=new \PDO('mysql:host=localhost;port=3306','root','root');
    $sql="select * from dvwa.users where user_id={$id}";
    $row=$pdo->query($sql);
    foreach ($row as $key => $value){
        print_r($value);
    }
}
catch(POOException $e){
    echo $e->getMessage();
}
?>
```  
  
我们知道通过GET方式来获取user_id,在sql语句中，直接把用户所输入的user_id值当作查询的条件，也没有任何的过滤等等，是可以直接构造Payload，看下面示例：  
```
http://127.0.0.1/sqltest.php?user_id=1 or 1=1
SQL语句为---select * from dvwa.users where user_id=1 or 1=1
原本的语句中没有加单引号或者加转义的函数，所以并不需要单引号
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU9Tnp60jIqpQbib5a1eY7Bb5cicMYicEeDtsxVFKo81O4Su8YuS4r6XGMpmMUT0l9kkuNZKnZFrWNbA/640?wx_fmt=png&from=appmsg "")  
  
当然这是最基本的，目前市面上的设备或者系统基本不会这样写，因为这种无过滤的SQL语句大多被框架和书写规范给杜绝掉了。很多师傅在面试的时候大多面试官会问，怎么防御SQL注入，大多人会回答进行预编译处理，下来看一个使用预编译  
用法错误的例子：  
```
<?php
$id=$_GET['user_id'];
try{
    $pdo=new \PDO('mysql:host=localhost;port=3306','root','root');
    $sql="select * from dvwa.users where user_id={$id}";
    $stmt=$pdo->prepare($sql);
    $stmt->execute();
    foreach ($stmt as $key => $value){
        print_r($value);
    }
}
catch(POOException $e){
    echo $e->getMessage();
}
?>
```  
  
这里使用 PDO 的   
prepare  
 方法准备 SQL 查询语句,但是SQL执行语句还是把用户输入的点直接带到查询条件中，从而存在sql注入漏洞 。下面看一个可以防御SQL注入的最基本的写法：  
```
<?php
$id=$_GET['user_id'];
try{
      $id=$pdo->quote($id);
      $sql="select * from dvwa.users where user_id={$id}";
      $row=$pdo->query($sql);
      foreach ($row as $key => $value){
          print_r($value);
      }
}
catch(POOException $e){
    echo $e->getMessage();
}
?>
```  
  
$pdo->quote($id)  
是 PDO 对象的一个方法，用于对字符串进行安全的转义和引号处理。例如，如果   
$id  
 的值是   
O'Reilly  
，那么调用   
$pdo->quote($id)  
 后返回的结果将是   
'O\'Reilly'  
。转义后的字符串可以直接用于构建 SQL 查询中的参数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU9Tnp60jIqpQbib5a1eY7BbNad6qZ5UT4WyUEkyX9PNrCQbDYyj4Z70AzJbvtQOpj37icMLxGLkic3A/640?wx_fmt=png&from=appmsg "")  
  
这是一种方法，还有一种预编译可防御SQL注入的写法：  
```
<?php
$id=$_GET['user_id'];
try{
    $pdo=new \PDO('mysql:host=localhost;port=3306','root','root');
    $sql = "SELECT * FROM dvwa.users WHERE user_id = :id";
    $stmt = $pdo->prepare($sql);
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    $stmt->execute();
    foreach ($stmt as $key => $value){
        print_r($value);
    }
}
catch(POOException $e){
    echo $e->getMessage();
}
?>
```  
  
$stmt->bindParam(':id', $id, PDO::PARAM_INT)  
: 这个方法用于将参数绑定到准备好的 SQL 查询语句中。在这个例子中，将变量   
$id  
 绑定到查询语句的   
:id  
 参数位置上，并指定参数类型为整数（  
PDO::PARAM_INT  
）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU9Tnp60jIqpQbib5a1eY7BbibBkyR5uXeeBFkXfRItMfn0NTN3SCt2wWDwZIicialqLgFcS5Sr6yLwHQ/640?wx_fmt=png&from=appmsg "")  
  
  
**02**  
  
  
**实战审计通用SQL注入**  
  
****  
  
在审计某cms系统时,  
在后台发现执行SQL语句的模块，抓包看看路由怎么走  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU9Tnp60jIqpQbib5a1eY7BbRw7h2dqQvjRPp8H0Na5eqiatc90HQefDkQUxHicpH2546GJibfHxuibBRA/640?wx_fmt=png&from=appmsg "")  
  
  
抓包看看路由怎么走，可以看到是sysCheckFile_deal.php文件，执行SQL语句的参数为sqlContent  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU9Tnp60jIqpQbib5a1eY7BbpCeXicicOwIn8Lsn7PScoWvB3vvR4v3Ta2bFARsewqFOBAA1TskFK0jw/640?wx_fmt=png&from=appmsg "")  
  
其中，swith是一个控制变量，当mudi的值为sql时，执行SqlDeal函数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU9Tnp60jIqpQbib5a1eY7Bbf37zkVIMwQxRkib2MsickbMicxiby0icicib2icrqxLEg2Vg6KD2Lqs6y91ickQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU9Tnp60jIqpQbib5a1eY7BbW0KI6gnXfJSUSpqBW7MsQba1hZ5H4bwSibmX409ukEqoGGtfATCm3ibg/640?wx_fmt=png&from=appmsg "")  
  
跟踪一下SqlDeal函数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU9Tnp60jIqpQbib5a1eY7BbpCpMB6YLj1QbWzlv7SpGstRZLphgWwFamHJZ5caiaJplRvNNl3icO5gQ/640?wx_fmt=png&from=appmsg "")  
```
  if (strlen($sqlContent) == 0){
    JS::AlertBackEnd('SQL语句不能为空.');
  }

  $newSql = strtolower($sqlContent);
  if (strpos($newSql,'into outfile') !== false){
    JS::AlertBackEnd('SQL语句中不能含有内容“into outfile”.'
    );
  }elseif (strpos($newSql,'global general_log') !== false){
    JS::AlertBackEnd('SQL语句中不能含有内容“global general_log”.');
  }elseif (strpos($newSql,'0x') !== false){
    JS::AlertBackEnd('SQL语句中不能含有内容“0x”.');
  }
```  
  
  
第一个if过滤掉了sql语句为空的情况，strtolower函数将$sqlContent(SQL语句)  
  
中的所有字符转换为小写字母，并将结果保存在 $newSql 变量中strpos函数的  
  
作用是查看$newsql变量中是否包含'into outfile'，如果包含，则为ture，剩下的if  
  
语句是为了过滤掉sql语句中的'into outfile'、'global general_log'、'0x'  
```
  $urow=$DB->GetRow('select MB_userpwd,MB_userKey from '. OT_dbPref .'member where MB_ID='. $MB->mUserID);
  $userpwd  = OT::DePwdData($userpwd, $pwdMode, $pwdKey);
  $userpwd = md5(md5($userpwd) . $urow['MB_userKey']);
    if ($urow['MB_userpwd'] != $userpwd){
      JS::AlertBackEnd('登录密码错误！');
    }
  unset($urow);
```  
  
该语句使用了一个名为 $DB 的对象，通过调用对象的 GetRow() 方法来查询数  
  
据库中的一行数据。查询的 SQL 语句是   
'select MB_userpwd,MB_userKey from '.  
  
OT_dbPref .'member where MB_ID='. $MB->mUserID  
，其中包含了表名和查询条  
  
件。  
OT_dbPref  
 是一个常量，表示数据表前缀。  
$MB->mUserID  
 表示当前用户的 ID。查询结果将会返回一行记录，包含了两个字段   
MB_userpwd  
 和  
  
MB_userKey  
 的值。这一行记录被赋值给变量 $urow，可以通过  
  
$urow['MB_userpwd'] 和 $urow['MB_userKey'] 分别获取这两个字段的值。  
  
之后则是核对密码，密码核对成功则开始执行sql语句  
```
  $sqlArr = array();
  if (strpos($sqlContent, ';') !== false){
    preg_match_all( "@([\s\S]+?;)\h*[\n\r]@" , $sqlContent . PHP_EOL , $sqlArr ); // 数据以分号;\n\r换行  为分段标记
    !empty( $sqlArr[1] ) && $sqlArr = $sqlArr[1];
    $sqlArr = array_filter($sqlArr);
  }else{
    $sqlArr[] = $sqlContent;
  }
```  
  
定义$sqlArr为空数组，之后使用strpos函数查找sql语句中的分号，如果没有分  
  
号，直接把$sqlContent的值赋给数组；如果有分号，则使用preg_match_all函  
  
数使用正则表达式来匹配 SQL 语句中的分号，并将分号前面的内容作为一个完  
  
整的语句存储到   
$sqlArr  
 数组中。由于   
preg_match_all()  
 函数的返回值是一个二  
  
维数组，需要将其中的第二维提取出来。如果   
$sqlArr[1]  
 不为空，则将其赋值给   
$sqlArr  
 变量。最后使用array_filter函数，由于没有给他传递回调函数，所以默  
  
认情况下，函数会过滤掉所有值为   
null  
、  
false  
、  
''  
 和   
0  
 的元素，并返回一个新  
  
的数组。可以发现可以使用query来执行sql语句，复现时构造恶意的SQL语句即可。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ssAcvVwPLCU9Tnp60jIqpQbib5a1eY7BbleLibAggCTO6AZ4fFumhZvKYVaGE2flnfz5Ra0FXvJS0sib6MOQrf6hw/640?wx_fmt=png&from=appmsg "")  
```
SET GLOBAL/**/general_log='on'   等

```  
  
  
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
  
