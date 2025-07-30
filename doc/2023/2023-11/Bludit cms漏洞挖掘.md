#  Bludit cms漏洞挖掘   
 船山信安   2023-11-29 00:00  
  
## 漏洞分析  
  
第一次听说这个cms，也是atao师傅告诉我的，源码地址-https://bludit.com/  
  
新奇的地方在于不依赖数据库，数据以json形式储存在文件里，我一开始的思路就是去找他的文件写入的点。  
  
入口文件如下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXNNKQPJlOlXKSRQKaFdn5cb9ZwrZyGWc1zn623h3icMBGlmS0gGGJAtw/640?wx_fmt=png&from=appmsg "")  
  
$url 在 init.php 中定义  
  
此文件只有声明常量，包含php类文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXbv0VpsPiaHRRFAMKEAA53Exeeib1tNO166kV65ibVL6CDQzdfzC7vE9AA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXbdPlERBlUbtwRam3icvXzJdVibhp0dYBl3N7fhXcItQ0akMHYrC0YViaA/640?wx_fmt=png&from=appmsg "")  
  
在edit-category/general路由 中，可以修改数据，然后写入文件中，对应的文件处理如下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXD6aclUgLmibUqN6JNDf81EyTQVUlfGq8pYer0SicL6WaicHaPxgTsKM5Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXfmMMWdnLeTE8hJLWJkS422zibUNdkgNwjT6CctYibic8Mh6nxjRZ0vs6Q/640?wx_fmt=png&from=appmsg "")  
  
直接将$_POST整个数组传入，感觉有可以利用的点，一系列的处理如下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXAswKyPD9jYliasP1ibyiaDyk7YHCcwkmbxTBNMAAM7PdIDicl1GMR3gxxw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXcRiatX8zfK9MlvXvdUrEZWglF6wurjolsKLQUYV8EnfVZ6gwhPlQ2zA/640?wx_fmt=png&from=appmsg "")  
  
这里会将一些参数做一个strip_tags 的处理，但写到newKey里。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXSwVvv6iagZ7qUm2tNlXo5xahFbL7pQs0UjQVibcMVWPypvaHNa45Rn8g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXNWbVGEpsaaTMLs3YplMmOlibbgFFaMtQCeUQ6OuhmdmrYUC8MM3ibbeA/640?wx_fmt=png&from=appmsg "")  
  
他确实写进去了，但发现在save方法的时候，拼接了第一行defined('BLUDIT')or die('xxx');，妈的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXBAOo5vrjt25fEia5BQepV5pCiaXy8qI5rnkfoLc9WArYNylhVia7gLUNw/640?wx_fmt=png&from=appmsg "")  
  
这几乎在每一个文件中都存在，除过入口文件。而且此常量，也只在入口文件中声明，这就导致我们即使可以通过一些拼接手段注入代码，在没有文件包含的情况下也没有办法利用的，不过我没找见。  
  
无能为力只能写个存储xss了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXLuUEtu16rBeNeCdDBLLkHvvibqKewNvwNL3xib4dvRjv4xWAqiaVlu2yQ/640?wx_fmt=png&from=appmsg "")  
  
后台提供了安装插件的方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXfJRquJUuOdgLtBCjjWlyIcnILbWgB2UwnBaMicKfLxhwplk6T3Uia7GQ/640?wx_fmt=png&from=appmsg "")  
  
不过插件都是在本地的bl-plugins文件夹里，然后通过activate将其加载进来。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXpfshiacrWy0d6RqYyXWwNjxQVB0QS03ujKZtE26ocZsdYHU0qxwMK8w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXnE6Yc23Y5gpmy3vOPfMM9QS6wgpziciaUiayNzMTs9Sib653hNCpoH7bJQ/640?wx_fmt=png&from=appmsg "")  
  
此处的 $plugins['all'] 是 admin.php 文件中包含了 这个文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXZShoNfIchVXwfwwPxOB1muk3EWJg1SA8YS3rYiaByQ1K9peiamPRPTYQ/640?wx_fmt=png&from=appmsg "")  
  
然后此文件中实例化了所有的插件类，将其存入数组中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXxpex9AdWGhXP9UjkicfWHK8RutsAiahywceSB6jdeEkzribxU3shPLZEw/640?wx_fmt=png&from=appmsg "")  
  
在site.php 中有如下调用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXPHksb1f5zv2FEUyy8lX7XCwCicPDhvPk30LiatJic4YKKJxT9icwcEo0Ig/640?wx_fmt=png&from=appmsg "")  
  
这里会遍历存在该type的插件，并调用其beforeall方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXcMXHFTmfMLU1r0iaXBYrHCKRRUVDU9qicEm83nia6KrH07KkuuQpSIrVw/640?wx_fmt=png&from=appmsg "")  
  
但其实只会调用已经activate的插件的beforeall方法，所以我们需要先在后台把对应插件下载下来。  
  
在插件中找到一个可以利用的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXbcczPxiadpXhO9FtSCPXwnXmpyrd26PV43vNdMDBdelV0CyXE1BTibfQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXUKPvR4hxjYgOT6NYX3icQAX4Ria5yaJWLtglWTCCaicJRxbMeRhk6fib0w/640?wx_fmt=png&from=appmsg "")  
  
跟进downloadfiles方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXia50ictH1WKjicmqj2t69iad2xPKr2f7Yia8ZdP9S3Mm9TbwLmk9Qt0at1w/640?wx_fmt=png&from=appmsg "")  
  
跟进TCP::download，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXj67I2JsuWLV4Tvr9x9iaqcEdpiavusybzy3lJOlgXWeUnzqgyIEU0kbw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXnRMl6M0xqn7BibaNIiblxkz21YQwt6iaN5Zupb50iafHxXKZzCWYcIfa8w/640?wx_fmt=png&from=appmsg "")  
  
就是从url获取内容，然后写入目的文件中，最后解压到目的文件所在的目录。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXdxoGD1rOWK1QSvx1RUsY5g2EY1eGkBKTfSQYYmfiadzEezBrDKlAF3g/640?wx_fmt=png&from=appmsg "")  
  
也就是 图片中的 romote-content 目录中，那么我们就可以构造一个压缩包在vps上，然后修改source值就可以写入木马文件了  
  
这个漏洞感觉跟 极致cms后台的一个漏洞很相似。修改source为我们的恶意服务器，并上传带有木马的压缩包。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXvrsKLBtKqmT61IDPZhFhzzH8Eicyib8NfR2TibFOUeEDjN9bP5NKJ1miaA/640?wx_fmt=png&from=appmsg "")  
  
save之后 trywebhook  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXtibAI7IVBLIhgL61hPPtbkhDcOcONnjj0skYKfgOJ0LicmLWo86O3hNg/640?wx_fmt=png&from=appmsg "")  
  
这里的try webhook就是把webhook写入配置文件中，然后访问对应webhook的路由，就会去执行该插件的beforeall方法，从而导致我们的恶意文件被下载解压。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elXIra0kHiaibjT0eOH9rI3WNPeKgbatwIDiaRBQlWdmMH4YMXiciadBiaOe1Zw/640?wx_fmt=png&from=appmsg "")  
  
成功getshell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicO1SEzUIjMyjgnc5hNd2elX3LP11GWsD2Ql2h1oEWt6LSZ3ghOcAVyUM7xIdFdaJ5u4WxGWgY5Isg/640?wx_fmt=png&from=appmsg "")  
  
来源：https://xz.aliyun.com/ 感谢【  
j1ang  
】  
  
  
