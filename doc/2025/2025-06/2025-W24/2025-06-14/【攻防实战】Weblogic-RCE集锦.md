> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NTU2NjA1Mw==&mid=2247503078&idx=1&sn=dcff53e08a56091f873b1504dbd66a57

#  【攻防实战】Weblogic-RCE集锦  
原创 平凡安全  平凡安全   2025-06-14 12:00  
  
**「直到看见平凡才是唯一的答案」**  
## 「WebLogic未认证RCE」  
### 「0x01 漏洞简述」  
  
发现 Weblogic ConSole HTTP 协议代码执行漏洞，漏洞等级：严重，漏洞评分：9.8。  
  
远程攻击者可以构造特殊的HTTP请求，在未经身份验证的情况下接管 WebLogic Server Console，并在 WebLogic Server Console 执行任意代码。  
### 「0x02 影响版本」  
  
Oracle:Weblogic:  
  
10.3.6.0.0  
  
12.1.3.0.0  
  
12.2.1.3.0  
  
12.2.1.4.0  
  
14.1.1.0.0  
### 「0x03 绕过漏洞」  
  
访问以下URL，未授权访问到管理后台页面（低权限的用户）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VqbbsyHxYKEPKMcCAAUrTZq9uUjprhpcmyYApslnPiah9D8ocrCQXAZA/640?wx_fmt=png&from=appmsg "")  
  
发现我们现在是低权限的用户，无法安装应用,所以组合下面的漏洞可以继续利用  
### 「0x04 代码执行漏洞」  
  
结合绕过漏洞，远程攻击者可以构造特殊的HTTP请求，在未经身份验证的情况下接管 WebLogic Server Console ，并在 WebLogic Server Console 执行任意代码。  
#### 「远程命令执行方法一」  
  
利用  

```
com.tangosol.coherence.mvel2.sh.ShellSession

```

  
执行命令：（利用DNSLOG）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VKQVRbrLokiciczuvs5lN2jVIXbkJpopQNlKzibOahWgXAsViaIDwTWSuqQ/640?wx_fmt=png&from=appmsg "")  
  
成功执行：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VyjiaiaooZLIQW8sckFria6qT9YNQPEM6icE5QlxEMmrwZFe34HsEHja9sg/640?wx_fmt=png&from=appmsg "")  
#### 「远程命令执行方法二（通用性高）」  
  
首先需要构造一个XML文件，并将其保存  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VzDs2MeuDmMnLKwMChcWGh4TtN3kcvAPHaB43SbM7ibzKVsT3srRRh5Q/640?wx_fmt=png&from=appmsg "")  
  
然后通过如下URL，即可让Weblogic加载这个XML，并执行其中的命令：  
  
成功执行：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VV2ZvSUGl8fMrMicSFAoKIQCLBpxhDy2ibXnicvKial4VuDODOkydlysic4g/640?wx_fmt=png&from=appmsg "")  
  
收到响应  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7V2t1oWZB1nSnjkmQ4SE9O6qBEPzYvt6uzv1lWcak3y6WVoJ3QLcy0icA/640?wx_fmt=png&from=appmsg "")  
## 「Weblogic XMLDecoder反序列化漏洞」  
### 「0x01 漏洞描述」  
  
Weblogic的WLS Security组件对外提供webservice服务，其中使用了XMLDecoder来解析用户传入的XML数据，在解析的过程中出现反序列化漏洞，导致可执行任意命令。  
### 「0x02 漏洞实战」  
  
访问如下链接，存在下图则说明可能存在漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VQ4iaH4IVK66wLGCM9T2Lcl5d6NKicB3ic1Tov9JerCXo2DGtwqJlOIrzg/640?wx_fmt=png&from=appmsg "")  
#### 「工具检测」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VnjlalSylYgdfFarHX5cVDh6zUqUdbUDHd0UKCfpjeUH7I3mLChIcuA/640?wx_fmt=png&from=appmsg "")  
#### 「反弹shell」  
  
发送如下数据包（注意其中反弹shell的语句，需要进行编码，否则解析XML的时候将出现格式错误）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7V1UG4jkQKqQcIb7pnSFiaVljSXH3HNkjQQKpncnE1whl65Jxoibic8V00g/640?wx_fmt=png&from=appmsg "")  
  
成功获取shell：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VADgiaEoS3J8fxUrwFeThEHM9XsicpwFwVl6gZfIgfJ5PzuPkVLypxbHQ/640?wx_fmt=png&from=appmsg "")  
#### 「写入webshell」  
  
发送如下数据包，写入webshell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VcSrqHUBicft4HbvmkNqzmoK0m2NFrnoMlk0dIRUbN7peoGv98HMzibNw/640?wx_fmt=png&from=appmsg "")  
  
成功输出内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VeWMN5sgSfHkZUMEtcVz1XiaWWPn1fIebdZuxmC22q4hjLB974p8a4Qw/640?wx_fmt=png&from=appmsg "")  
## 「Weblogic SSRF漏洞」  
### 「0x01 漏洞描述」  
  
Weblogic中存在一个SSRF漏洞，利用该漏洞可以发送任意HTTP请求，进而攻击内网中redis、fastcgi等脆弱组件。  
### 「0x02 漏洞实战」  
  
测试该漏洞。访问一个可以访问的IP:PORT，如  

```
http://127.0.0.1:80

```

  
可访问的端口将会得到错误，一般是返回  

```
status code

```

  
（如下图），如果访问的非http协议，则会返回  

```
did not have a valid SOAP content-type

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7Vme02JEpku1RjE3XPsgTtllHfrVpfianMY0wIoxGcEPlgZQ2poF2pibpA/640?wx_fmt=png&from=appmsg "")  
  
修改为一个不存在的端口，比如  

```
http://127.0.0.1:7000

```

  
将会返回  

```
could not connect over HTTP to server

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VlPTM7CwTYQtyicFUJwISLOxRSbeIWyoKuQRVEALWVdMaMA6AB9Oabqw/640?wx_fmt=png&from=appmsg "")  
  
通过错误的不同，即可探测内网状态。  
## 「Weblogic WLS Core Components 反序列化命令执行漏洞」  
### 「0x01 漏洞描述」  
  
Oracle 2018年4月补丁中，修复了Weblogic Server WLS Core Components中出现的一个反序列化漏洞（CVE-2018-2628），该漏洞通过t3协议触发，可导致未授权的用户在远程服务器执行任意命令。  
### 「0x02 漏洞实战」  
#### 「第一种方式」  
  
直接运行下述命令即可（自行替换IP和端口）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7Ve54EEMGD5picTQQc4qI7Jmp7g8ibnq33RVxkwMS8sicZ0KEG3diaDq5v4A/640?wx_fmt=png&from=appmsg "")  
  
上图中最后一行Getshell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7Vj4x4JNsUXpnicicKpWgqXLSiasEqDe6YqYq4yUZRPCzSrFjoFibvDq5icCg/640?wx_fmt=png&from=appmsg "")  
#### 「第二种方式」  
##### 「上传shell」  
###### 「方式一：」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7Va4ibicQmB9E1KicpJichXA852EQ9AiadBUCDXvpYZ3CxZeoib2Ycf2oDic1LA/640?wx_fmt=png&from=appmsg "")  
  
得到Shel  
###### 「方式二：」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VtA6FQT2Hyv1HZ3xQs6KAicjUkKYicqDle6T9NBG5JJFOVjWYw3H2icqxA/640?wx_fmt=png&from=appmsg "")  
##### 「执行shell」  
  
输入Shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VoK4gIIZnib8sYvYeAMjyzCCorvq8TJnZruQ5hZhqiaj67gewV0s9vLGA/640?wx_fmt=png&from=appmsg "")  
## 「Weblogic 部署war包Getshell」  
### 「0x01 爆破弱口令」  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7V1r908awiaYzpjZyUXYuGFnECxWhibxQjDMmynVQJ2xzRKBia7TJ9SX7Yw/640?wx_fmt=png&from=appmsg "")  
### 「0x02 任意文件读取漏洞的利用」  
  
可见成功读取passwd文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VMAF21vlIFibk4oNc0uUIhWSOb4sFYtLHfy86bWGEcsg5eNPpK0d1lIQ/640?wx_fmt=png&from=appmsg "")  
### 「0x02 读取后台用户密文与密钥文件」  
  
访问  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VOez8BetHicvQuDbNIgEhkoadqBUp988Z2SIJHY6nt4AV652JibIDByOA/640?wx_fmt=png&from=appmsg "")  
  
全局配置文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VGYcjrZ6Fm54dYBHqFDtMfJRMgr6TXF0zXhe7deRm1h7wPOxDBtojIg/640?wx_fmt=png&from=appmsg "")  
### 「0x03 解密密文」  
  
可见，解密后的密码和暴力破解的密码一致，说明成功。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VbmDlvkQXvPkNS96MLIGMQVicxWRUDsaeYU5dGB7qw784XicicoSibKnWLg/640?wx_fmt=png&from=appmsg "")  
### 「0x04 后台上传webshell」  
  
获取到管理员密码后，登录后台。点击左侧的部署，可见一个应用列表：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VoibSial1cK2iarjWbx5RBQj8ah9nCqShVSbHMfqP9YnWtCniaRwdyBxy3g/640?wx_fmt=png&from=appmsg "")  
  
点击安装，选择“上载文件”：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VL2LY3XibUFGUZzibj3GdJV71h9pCavrGTlr0Vn0KUA3ew5j9ju62H5Iw/640?wx_fmt=png&from=appmsg "")  
  
然后选择制作好的 war 木马文件包，点击下一步：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VliaY26GhhCydkrcU7yI6xxYKyToYicfuEmNKflY3cQcEbE1Rpf5FdkpA/640?wx_fmt=png&from=appmsg "")  
  
一直下一步（这里注意点击的是上边的下一步，不要点错了）：  
  
然后点击完成  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7Vwd8uO1nOnU0wia1nuh5FewwKEoXOwHx5OmGM7atU1NiaNDTU1WJu69PQ/640?wx_fmt=png&from=appmsg "")  
  
保存  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VBwPKzt3FzEks3jBgGzPftpEO0tUHtTWQaEenNUPNXMfxnBW9pXwiamA/640?wx_fmt=png&from=appmsg "")  
  
部署完成  
  
使用webshell进行命令执行：  

```
ifconfig

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7V7xoTx9oMQk5PniaWvRIszwTIYgX0GIvOaQLmBWGicCkea1kek08NictVA/640?wx_fmt=png&from=appmsg "")  
## 「Weblogic base_domain任意文件上传漏洞」  
### 「0x01 什么是WebLogic」  
  
WebLogic是美国Oracle公司出品的一个application server，确切的说是一个基于JAVAEE架构的中间件，WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。将Java的动态功能和Java Enterprise标准的安全性引入大型网络应用的开发、集成、部署和管理之中。  
### 「0x02 漏洞描述」  
  
Weblogic管理端未授权的两个页面存在任意上传jsp文件漏洞，进而获取服务器权限。Oracle 7月更新中，修复了Weblogic Web Service Test Page中一处任意文件上传漏洞，Web Service Test Page 在 ‘生产模式’ 下默认不开启，所以该漏洞有一定限制，漏洞存在页面在/ws_utc/config.do。  
### 「0x03 影响的版本」  
  
weblogic 10.3.6.0、weblogic 12.1.3.0、weblogic 12.2.1.2、weblogic 12.2.1.3。  
### 「0x04 漏洞实战」  
  
console界面用账号密码登陆  
  
登录后台页面，点击  

```
base_domain

```

  
的配置，点击高级  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VlNpxJA8X8BdHLcoXNyx5MC13icibM7r3GibdqL9tWlbUP7JEQia7GE0c8w/640?wx_fmt=png&from=appmsg "")  
  
在“高级”中开启“启用 Web 服务测试页”选项：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VzwB7ywk29wXasxmEFD6ojRplo0gZKR1uk1zEJGfE0p8Xx0sZ3ht1aQ/640?wx_fmt=png&from=appmsg "")  
  
访问，设置  

```
Work Home Dir

```

  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7V9t0Yic01lpuryxg3lGArnFQiaXEUwia5rMJicWURGwIJjYfkfc2GwkI3Bw/640?wx_fmt=png&from=appmsg "")  
  
然后点击安全 -> 增加，然后上传webshell：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VxL3WMt2OBphuzQm4qjGFTKfria62Odviae3KWBHUNt6PlnWu7PibibobXA/640?wx_fmt=png&from=appmsg "")  
  
上传后，查看返回的数据包，其中有时间戳：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7VLEftgCaiczBnwMstAf6jxhJtq71SVyIj8mI67B7OzLBDKkRKFOVwQ5Q/640?wx_fmt=png&from=appmsg "")  
  
然后蚁剑连接，即可执行webshell：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyPAJyC1xvrSJobmgkfax7V9tzHIJOa57K7MZWo7WO4ibrUKYxE3bPs0Hz5uRlsxO5mxFo9VQ1f3BA/640?wx_fmt=png&from=appmsg "")  
## 「攻防交流群」  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpyPAJyC1xvrSJobmgkfax7V9sQ1XeEicsqOZU5ZPibovK8w6IBsDVPJEicqdYZWeenydex3MiaJakqa7w/640?wx_fmt=jpeg&from=appmsg "")  
## 「声明」  
  
文笔生疏，措辞浅薄，敬请各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
  
  
