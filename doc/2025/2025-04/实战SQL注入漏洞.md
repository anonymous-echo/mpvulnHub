#  实战|SQL注入漏洞   
原创 bcloud  蓝云Sec   2025-04-13 00:13  
  
# 声明  
  
任何网络安全相关测试均需取得授权，本文章中所有内容仅供学习交流，严禁用于商业用途和非法用途，否则由此产生的一切后果均与文章作者无关！  
# 前言  
  
一次渗透测试实战中的SQL注入，从延时注入耗费大量时间到用户名密码获取至整个网站数据信息泄露的一次真实记录。  
# 渗透开始  
  
首先开局登录框，任意输入用户名密码admin:123456，不行，提示账号不存在  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6duvmPribAibK3dm2s9EVcrRbWpo1qV6AgBck7YXFj9PiaoeBE5HuY2ibMg/640?wx_fmt=png&from=appmsg "")  
  
这下不好搞了，爆破了一下也没有爆出账号名密码，索性查看了一下插件，发现SQL注入插件有响应，去看看，哎嘿500，200状态码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln68b1vicGwJ09fxWNhPftia6t5ZMjI6ySGU2nwMrDKAPicHDawx5bSsJiabA/640?wx_fmt=png&from=appmsg "")  
  
先自己实验一下，account参数添加单引号服务器报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6icflEA0ibyoKskC6OibAxysicMnwwU48CY4ibIX99uAoT30Sc1jTYiaR4hmw/640?wx_fmt=png&from=appmsg "")  
  
再次添加单引号进行闭合，正常输出，我一看这包有的啊  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6uoynb30nia8Vg57jCIAIaJicIXX05sj8uEiacyjzYFSVpVicbuHjEFZbMw/640?wx_fmt=png&from=appmsg "")  
  
直接sqlmap工具梭哈，成功证明SQL注入，但是是延时注入，我一看这有点复杂啊，但是做一个安全人员肯定不能放弃  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6B5SjcWKw8Wic1PeOLxex5DNhsGb1oLe8gfR8fRNibXGfWMU3Ovgy4oQg/640?wx_fmt=png&from=appmsg "")  
  
直接--dbs爆数据库名，数据库名还挺多，其中有一个为该单位的缩写，比如河北建设（hbjs）这样子的数据库，那不就一一对应了嘛  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln67xfd6NH35jeHAichVg1GxojuamoeacF9SOKasibTcyHOte4Hr2HaaPXw/640?wx_fmt=png&from=appmsg "")  
  
直接爆破表名，md，这里耗费了一两个小时都没注入完，索性爆破到xxx_user表，这一看就有戏啊  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6kON4qYFtruYBBwWkhsf4NlLq9XPq048xZ7KrO1RDia8IvOFSCflEMBg/640?wx_fmt=png&from=appmsg "")  
  
这里在爆破user表中的列，又耗费了我一个小时左右才爆破完，最终拿到三个有用的列，这里有点粗心大意没有刚开始没有看见login_account列  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6nMsDb4OJia45zHX6T0Pa3Ttj9ydx3O7QRcCKCJr6O4yofic5T8H9ncIg/640?wx_fmt=png&from=appmsg "")  
  
所以先爆破了password列，哎嘿发现全是123456，弱加密的md5  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6mibibAkQYfVCScE0BJOo9VxSiaqEcRo4WyKquqA51kx0icvZFhWx6dGaww/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6qDfIVdqYBZsLqC1rLtN0lazN75Moic4zrDd6RsprkjEaJQiaTmNnga7w/640?wx_fmt=png&from=appmsg "")  
  
然后爆破了name列，有三个数据，其中只有1810xxxxxx的手机号回显与其它的不一样，显示禁用状态  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6PVXVXjm0KJQxia9Nibj86Y2wxhQbRO9xTle4BzDDolQP83Kf9F7PScJA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6yI2rgUIkPu0KlvME5Z7NvjVrO1p3yLM60fruG8yXt5sFzEZ6KIzrSA/640?wx_fmt=png&from=appmsg "")  
  
这里我再回过头去看user表中的列发现login_accout，哎哟卧槽，就是粗心大意之下，md又耗费了很久的时间，这里成功获取到五个账号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6RWibehzCZ2iaBZeqEFvZHiamWqnWpcBLxyia4sKDYgQuHucHGf02TfC1hQ/640?wx_fmt=png&from=appmsg "")  
  
其中13xxxxxxx开头的测试账号都是被禁用状态，只有1896开头的能够使用，这尼玛耗费三四个小时的延时注入成功获取到账号名密码登录后台，成功登录，里面数据还挺多就不给大家看了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6ddZX9LXGPyuhQ2AY0InTsM3XI0qaWA3ibc0La9iaqq6ZRwdO4ldH1D4A/640?wx_fmt=png&from=appmsg "")  
  
在后台找到一个文件上传点但是白名单校验，那没有办法了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln6gmFJba60aPLeh257eQl363deKia2FLNDAK7ZRKbWK51qZaZUXYbXO4A/640?wx_fmt=png&from=appmsg "")  
  
不过从开始的注入数据表可以发现还有其它的表名，直接资产测绘搜索发现其它账号也能登录，说明这个数据库是通用的，这尼玛发财了，哈哈哈全是数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/IS2RlFMDPK6fUQ5Lvah8EPyAhoYT8Ln617jF4OAd1ZibPvcAF8HiaRolxRibUlfP2C6qnIVmqLLIb1upgluc8Z0jg/640?wx_fmt=jpeg "")  
  
  
