#  kkFileView远程代码执行漏洞分析   
 哈拉少安全小队   2024-04-24 12:17  
  
kkFileView由于前台上传功能在处理压缩包时，从仅获取文件名改为获取文件名及其目录，导致出现了Zip Slip漏洞。这使得攻击者可上传包含恶意代码的压缩包并覆盖系统文件，随后通过调用这些被覆盖的文件实现远程代码执行。  
## 影响版本  
```
```  
## 漏洞复现  
  
复测版本：4.2.1  
  
下载地址：  
https://github.com/kekingcn/kkFileView/tree/v4.2.1  
  
使用IDEA搭建，并运行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6byMk77UCgX4X2oGQy7sdAEibm1g4SFia1J1y6ceXqD2ZyjZTiavY4VI1Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6E01Ir0SX4v6ia1sMyTDOiaQmyCvjdD3n5Nkib3FfeKle78Q3326hUEgag/640?wx_fmt=png&from=appmsg "")  
  
### RCE漏洞复现  
  
构造恶意的zip包  
```
```  
  
将zip包上传并预览，路径为我当前本地搭建的，不一定通用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6IxLOeSUWWmGOe99UqjPhRGRVxRGxfuubmFuYcgWR4VA5MReFRPM48w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6KVPhg5vMJBU0jE3jEdYEcFTI267fNySAVBKDVdtze29JGoExqyWv2A/640?wx_fmt=png&from=appmsg "")  
  
成功将内容写入到了   
uno.py  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6yZIdebiamiaLTInuhJ2TEf68BRMgccjEGsbr0YJhfBcxj4Mqial5FMkkw/640?wx_fmt=png&from=appmsg "")  
  
接着上传任意odt后缀的文件，并预览  
  
成功执行弹窗计算器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6rhsXQxicC3QJ4YSO0gcdqNkTCPx0vwzstOJiao7ocom5yLXQ2woMwvNQ/640?wx_fmt=png&from=appmsg "")  
  
## 漏洞分析  
  
根据  
https://github.com/kekingcn/kkFileView/issues/553  
 给出的漏洞点分析  
  
关键代码在CompressFileReader 类，该类主要将上传的zip解压，但是解压时获取文件名及其目录，导致可以覆盖任意文件内容和写入任意文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6Nkht9YrJFwQAJibSnyswo1ZH1YdYiadOeSicQsq03rHicDVhueqibTreYqA/640?wx_fmt=png&from=appmsg "")  
  
  
我们一步步调试看看，下断点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6poqCu21lqnZobWEXUdyHd7kXVxw8mUN2FV2xPH5UhZuPX40TMcBEug/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6lsBxgk2WibnxozGljMEk3dqJC7OU4QkVaFTXxx8q6lZdAh6mpYR47Iw/640?wx_fmt=png&from=appmsg "")  
  
  
在56行代码中，extractPath为文件路  folderName为上传的zip文件名称  
  
File file = new File(extractPath, folderName + "_" + File.separator + str1);  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6g3jictnpz8PqPhs8azKwB3Ewibz9E7KaofxcpaGPicC04gCaNfOn8xgHg/640?wx_fmt=png&from=appmsg "")  
  
  
在57行代码中  判断文件是否为空，为空就创建目录  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6RZUUJxHlDxSgEZ5yYQSibceINzIXjria2R93ElMYlH8noxPJFiaR0aicug/640?wx_fmt=png&from=appmsg "")  
  
  
接着创建文件流，但是他写入文件是将目录一下写入了，使用  
../../  
 即可导致任意文件内容覆盖  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN65wrgvC8pjSDGzicibYnkCQyEsIcLqEv6tETAPdA3gEFtc8KycQ3ksn2A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6icPv068Z92rf5FJyfRBwibDleL65lVaKqHaVDclKYq9u3OrhbzxiaRicTw/640?wx_fmt=png&from=appmsg "")  
  
  
虽然写入文件，但是没有调用uno.py的方法，根据大佬的方法  
  
目标在使用odt转pdf时会调用系统的Libreoffice，而此进程会调用库中的uno.py文件  
  
接着分析预览odt  
  
在  
OfficeToPdfService  
类中 将  
.odt  
 文件转为PDF文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN65wrgvC8pjSDGzicibYnkCQyEsIcLqEv6tETAPdA3gEFtc8KycQ3ksn2A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6icPv068Z92rf5FJyfRBwibDleL65lVaKqHaVDclKYq9u3OrhbzxiaRicTw/640?wx_fmt=png&from=appmsg "")  
  
  
并成功执行  
calc  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6BfJTrUSFkkQnoTXGYVLKohnqsFqpia0XHbFYHhPIHIeyy8ATCqnRbbg/640?wx_fmt=png&from=appmsg "")  
  
下面代码就是执行 LibreOffile    
  
builder.build().convert(inputFile).to(outputFile).execute();  
  
来分析一下   
builder  
  
从代码中    
builder  
 是    
LocalConverter.Builder  
 定义的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6zRy2e8h4LB1vTcI5EF8BX6O5icH8U7ywsiaWPyIyskLhWcHL9SVe65icg/640?wx_fmt=png&from=appmsg "")  
  
#### build  
  
LocalConverter.Builder  
 类实现    
build  
   
```
```  
#### execute()  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4uB69jictKBVWX730MgviaN6wfKQPdLhviaQMavPHm4cbrsJsiaWpjOZic0MEKGK3LbiaLGy9Xtdhjl4Bw/640?wx_fmt=png&from=appmsg "")  
  
  
这段代码定义了一个名为   
doExecute()  
 的方法，该方法用于执行文档转换任务。让我们逐步分析它：  
1. useStreamAdapters  
 变量用于确定是否使用流适配器。它的值取决于   
LocalConverter  
 对象的   
loadDocumentMode  
 属性和   
officeManager  
 的类型。  
  
1. 如果   
loadDocumentMode  
 是   
REMOTE  
，或者   
loadDocumentMode  
 是   
AUTO  
 且   
officeManager  
 是   
ExternalOfficeManager  
 的实例，则设置为   
true  
；否则设置为   
false  
。  
  
1. 创建一个   
LocalConversionTask  
 对象，用于表示本地文档转换任务。构造方法接受源文件、目标文件、是否使用流适配器、加载属性、存储属性和过滤器链等参数。  
  
1. 使用   
officeManager  
 执行上述创建的文档转换任务   
task  
。  
  
## 总结  
  
OutputStream out = new FileOutputStream( extractPath+ folderName + "_" + File.separator + str[0], true);  
  使用  
../../  
 即可导致任意文件内容覆盖  
  
builder.build().convert(inputFile).to(outputFile).execute();  
 转换pdf是启动了LibreOffile 并执行   
C:\Users\26927\Downloads\kkFileView-4.2.1\server\libreoffice\program\uno.py  
 脚本中内容导致RCE  
  
文中漏洞分析可能不准确，个人java水平有限  
  
  
