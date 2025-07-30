#  通过JavaScript进行漏洞挖掘思路   
原创 【白】  白安全组   2024-05-13 17:51  
  
本文针对js漏洞挖掘，其实从JavaScript中挖掘，也就是在js中挖掘敏感的接口漏洞，我们一共需要两个步骤，一个是通过工具进行js搜集，第二步就要利用工具进行js中敏感接口提取。  
  
首先我们需要针对js进行一个搜集  
# 1、URLFinder搜集js目录  
  
这里使用我使用windows版本进行测试  
  
测试方式：  
  
单个url  
  
显示全部状态码  
```
URLFinder.exe -u http://www.baidu.com -s all -m 3
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUbQbop1xd0Lic5XdvniaI1CkM3GNmbcYaGic0lpXEo8dygXiclrqfRDFrKUiaVHRmN64GxjFZ4TU8Ca8AQ/640?wx_fmt=png&from=appmsg "")  
  
  
显示200和403状态码  
```
URLFinder.exe -u http://www.baidu.com -s 200,403 -m 3
```  
  
  
批量进行扫描  
  
导出全部  
```
URLFinder.exe -s all -m 3 -f url.txt -o .
```  
  
只导出html  
```
URLFinder.exe -s all -m 3 -f url.txt -o res.html
```  
  
  
结果统一保存  
```
URLFinder.exe -s all -m 3 -ff url.txt -o .
```  
  
# 2、利用Findsomething插件  
  
上面我们会搜集出一些js文件，比如我这里检索出了一些后台的js文件，属于未授权的js文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUbQbop1xd0Lic5XdvniaI1CkMqIL7vumeCEx57KGkrWptW2icavWG3gvcnzbR50nqwM8iciauWE9zdbJbA/640?wx_fmt=png&from=appmsg "")  
  
那么我就可以访问这个路径使用谷歌的一款插件Findsomething  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUbQbop1xd0Lic5XdvniaI1CkM6X8ZssDKbicPdKOgKztREJzU18VwliasvYjbickof3rd1YiboHoFHiciaulg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1AUjJ6HpTUbQbop1xd0Lic5XdvniaI1CkM7F8yV8goZEwqcoJlScUz4czVlXb7LGSJZLLibOk5LsIFH0PNMV4ST2w/640?wx_fmt=png&from=appmsg "")  
  
通过这个插件我就可以快速找到一些接口，这里我们再进行一个接口的fuzz测试  
  
