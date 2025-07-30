#  dedecms 两个常见漏洞的复现   
 菜鸟小新   2024-08-25 17:48  
  
侵权声明  
  
本文章中的所有内容（包括但不限于文字、图像和其他媒体）仅供教育和参考目的。如果在本文章中使用了任何受版权保护的材料，我们满怀敬意地承认该内容的版权归原作者所有。  
# 简介  
  
## 版本  
  
5.7  
## 漏洞位置  
  
### 文件上传  
  
file_manage_control.php  
### xss  
  
article_add.php  
# 分析  
  
## 文件上传  
  
找到文件中的文件上传位置。![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjePtqC90ia5XREct7LnfW3HiaXpATRjMHIlsQgsqVhlEHaJRYOTBhQQNHw/640?wx_fmt=png&from=appmsg "")  
  
  
红框前都是对参数的初始化，找到文件临时存放位置，将临时文件保存到本地。之后删除临时文件。红框内$file_base = strtolower(pathinfo($file, PATHINFO_BASENAME));获取文件名$file_ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));获取文件后缀if (is_file($file) && $file_ext == "php")判断是否为文件和后缀是否为php如果此时一个条件不满足就好跳出后面的内容判断。如果我们上传一个php3为后缀的文件就可以成功(还是有其他访问绕过或使php文件可以执行的办法)。然后通过下面函数改名即可利用。![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cje3wNpmv9Cvzbm6T17Vc9nEdu4282Xmwhf0QYgw7DqudCIRJ0c85hFhg/640?wx_fmt=png&from=appmsg "")  
  
  
跟进RenameFile函数发现，没有进行过滤新文件名，只判断新旧文件名是否相等和文件是否可写。![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjezKbOjBRJ3EcGLG8H3rGMkjERj1UE4dE8uxAgQUybqZLENhEbWbBogA/640?wx_fmt=png&from=appmsg "")  
  
  
## XSS  
  
通过poc找到文件位置![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjeLaXO7NcCcmoLw1VSK0iabgK9CHoMfibE9oZGrgTkoaX2vrnwS2DKCTzA/640?wx_fmt=png&from=appmsg "")  
  
  
跟进makart()函数，该函数是准备创建静态html文件，![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjeQ3hsFqyRMaiaI1DvRRzIJQB3llfaYsnj7IrxiaRcUkicVputkULojB2QA/640?wx_fmt=png&from=appmsg "")  
  
  
继续跟进makehtml()函数![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cje8TNa9M3CY56kpLQy53BRNv5wFuwlRvBkPQxbwuiaJjcXjARB4k7VSsQ/640?wx_fmt=png&from=appmsg "")  
  
  
该函数前半部分有面两个重要的函数。$this->LoadTemplet();获取文章的模板$this->ParAddTable();处理文章需要保函的额外功能。例如投票。更进paraddtable()函数![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjen3J5W2NiaicSATxlpHibxIgvyJ0g3QQNsHRxiaxfrpXdOftfrqtUiaic8jyQ/640?wx_fmt=png&from=appmsg "")  
  
  
但是此时投票功能还没有实装到文章模板中。继续看到makehtml()函数后半部分![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjeDqTIS5JPjNoOv7fxwrRNAeibBzka9XldkqHkFBFMReicQXrkAubBvcaA/640?wx_fmt=png&from=appmsg "")  
  
  
直接看到最后红框中的两个函数。$this->ParseDMFields($i,1);判断哪些模块是需要加载到文章模板中的，并对其进行标记和计算出需要加载模块的数量。方便后续将需要的模块加载到文章中。$this->dtp->SaveTo($TRUEfilename);将模块加载到文章中。跟进saveto()函数![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjevau9jCgwKhfPqyiajRIbSWvwrKibjxtROd3MYibcMic04snc00G9GUukVQ/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到文件写入的功能函数了，继续跟进getresult()函数![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjenibTJfJuF9ze3JjOTJ0mibEZqibEgOLsjWhp9twoZaCCicl8xddThJT9RA/640?wx_fmt=png&from=appmsg "")  
  
  
我可以肯定的是在26号模板中就存在投票功能的模块并且写入了resultString参数，你可以自己去看看。  
# 复现  
  
## 文件上传  
  
1、找到文件上传位置![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjeVTFibibSUTUWpIzFyicDccE6to23njFiaOU3HdIHStjgBSImVibHBpEvnWg/640?wx_fmt=png&from=appmsg "")  
)2、上传一个带有一句话或其他的文件，但是文件需要时php3或是其他为后缀的![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjeW0Z7QjdEeXpWAbk6GdHymMgQXrXESf8hea8xtmSz2xEeohDfVTpX1Q/640?wx_fmt=png&from=appmsg "")  
  
  
3、修改文件名为1.php![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjeF4f9MC74384H7DXVOra9HN6f2IZSd0iaxKMcrVXTxwNVRRewX5OY1sw/640?wx_fmt=png&from=appmsg "")  
  
  
4、访问利用![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cje9YvicQhsCichgVAjga6DB1ZIQyL0dxPLr8cvOsABialUdM6cCWqY7icCmg/640?wx_fmt=png&from=appmsg "")  
  
  
## xss  
  
1、找到文章发布位置，准备新添文章![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjeSlibeX0mvlpJmmggXJCXBZNnSib2JvcleF52ia4zZwLHFsjjCg8PVfIkg/640?wx_fmt=png&from=appmsg "")  
  
  
2、添加文件名和主栏目后，新增一个投票![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjeLic3XMghjz8hk6ewbu3nYGgfxwpiasWzgBAnlEHHGTcQy6uFUAmn0AlQ/640?wx_fmt=png&from=appmsg "")  
  
  
3、在投票名称位置加上一个测试js代码，然后保存文件。<script>alert(1);</script>![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjeeJPAicvtUhDVF7pISSKZSWiaakHrNVEQS88jQj1vEJNf8HG737otj7tw/640?wx_fmt=png&from=appmsg "")  
  
  
4、访问文件![](https://mmbiz.qpic.cn/sz_mmbiz_png/rgHsQiafgQSiaibRTNqtw3CFKick33qq0cjehjX0QRSWzmUoCvvZaUTlp5gB1heATygCic7CFH1LUkib6uzVdRuxhoxg/640?wx_fmt=png&from=appmsg "")  
  
  
# 总结  
  
还得练，只找到了一小部分。该系统还有很多其他漏洞。  
  
  
