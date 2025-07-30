> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAwMjQ2NTQ4Mg==&mid=2247499565&idx=1&sn=34fc51e56817b871ded40c91db6234c1

#  记一次从登录框到前台rce  
 Khan安全团队   2025-06-29 12:37  
  
欢迎转发，请勿抄袭  
  
        在某次众测项目中，开局发现是一个登录框，于是想放弃。经过弱口令工程师一顿输出，最终getshell。于是就有了这次分享～  
  
1  
  
接口未授权挖掘  
  
        在网站未登录的情况下，由于不知道后台接口。唯一办法通过js文件、路径扫描。通过这种收集方式使用burp进行批量扫描，分别探测GET/POST请求。观察响应包跟状态码。判断响应包，确定存在未授权后，再构造数据包。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4Vv0VYLOkaEwO2M6wAQZVsFQve07C4ydMhkjTMorSiaTAImLL1q2K0RtA/640?wx_fmt=png "")  
  
2  
  
突破登录框  
  
       在测试站点中，很多时候不提供测试账号。此时，就需要一个尝试爆破账号，但是有时候会有验证码(  
重发登录包，50%假验证码)。正好这次没有验证码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4VZEZjJzABEPodPJIkRH8ZblyicJqeialiaRJlPlXyiaUzB2rtXkR4dCud8Q/640?wx_fmt=png "")  
  
拿到这种网站，先判断一下有无用户名猜解。判断存在与不存在账号。测试常见的admin、admin321，观察它们之间的提示。就算发现有这个admin账号，但是有密码错误锁定的情况，那么就尝试爆破账号。(  
手机号码与常规账号，总会有测试账号或者总会有人设置弱口令)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4Vhmia4HD9nnXLyw6BdJfMOLwxqbUvmdX7t7zwGic9cwPvcEB2we1LOOzg/640?wx_fmt=png "")  
  
密码设置为弱口令123456，账号为字典进行爆破，根据响应包大小进行判断。最终拿到测试账号。  
  
3  
  
后台漏洞挖掘  
  
       通过测试账号进入后台，额外注意接口跟上传下载点。由于这个我们没有网站代码，只能访问相关功能，并burp插件Autorize记录探测那些接口存在未授权。通过页面翻找，找到一个正常的上传点。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4VXO4pXiaut5mZ1sKDjf7bODyG0Y0JMfarMSo8wtxzlykchQVQ69Nz9Rg/640?wx_fmt=png "")  
  
构造正常上传一个txt文件，发现这个功能先是上传后并读取该文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4V5J3bJHjGicDyPibDWTj42cKu8JovADstwrCvWCqzpRVPH8pk03GoCzOw/640?wx_fmt=png "")  
  
并尝将cookie凭证删除，发现仍然可以上传。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4Vzkib79ebkW3ApTE5ibmYWkSVHMPLSadnXibAtx7BE8Xpcpn1K1w6x7HPg/640?wx_fmt=png "")  
  
那么将它转成是前台的上传漏洞了。经过测试发现，目录也是可以穿越的，文件名可以任意。读取文件接口也存在穿越问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4V63slGch2kh3qicia53pqbsicWjxzFxEiayYjx69KicicNop8wlhIOjRd2csQ/640?wx_fmt=png "")  
  
根据接口判断，该网站是可能是springboot的，显然上传jsp是不行。那么还剩下两个方式拿权限。一是上传ssh登录凭证、二是写定时任务反弹回来。扫描了一下ip，发现ssh端口未对外。于是尝试定时任务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4VdBOwz1sK2DJIPCyDH9b9CKbRXCQkOeUXSNPukeMhLHynrugkicw0tdQ/640?wx_fmt=png "")  
  
等了几分钟没反弹回来，通过于是又看了一下定时任务的日志。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4Vl1jXNuMDw44ehdNOBt1K4AQJOadBcianhv44Oic9727NOAAFE0YPEfMA/640?wx_fmt=png "")  
  
最近的定时任务日志是在前一天，要么就是服务器时间慢了一天，或者是定时任务管理器在前一天被停了。再次尝试写定时任务。  

```
* * * * * *  whoami>/tmp/data.txt
```

  
仍然无法读取到tmp下面的data文件，至此确定定时任务真没起来。  
  
4  
  
柳暗花明  
  
        难道真的无法getshell了吗？  
通过下载接口，读取root用户的历史命令。  
找到网站路径。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4VRenbDOU7ebwWgmpbaKSwEMdhia8kac34HbLicgMic9c4M3xibWDicdQQf8w/640?wx_fmt=png "")  
  
看到这个webapps，瞬间精神了。直接构造上传路径，并输出jsp文件。上传shell～  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4VhrwwMLvV6iayqK7VFrAqcTKzzaTt713nEJ7gcK5gx7ibbKaboXzzjDbQ/640?wx_fmt=png "")  
  
哥斯拉连接上去，上个whoami截图。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4V66f24s74MXHyVloKmKUSmBn0dciagmYw9DrPpynG7K1aL9ZzJONWgqA/640?wx_fmt=png "")  
  
通过检查网站文件，发现是一个tomcat里面有个目录是springboot。但是网站没见到其他的jsp文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BDzX6q5EsXkJbdvGS9q6rqV5eA1RZb4VJHl4vjqCfA4oc7a6JYhxOCOa1gXUx0B8kdpLRXS6iaiaPmgGibIxc1cIw/640?wx_fmt=png "")  
  
这种开发方式属实少见。网站也是通过war方式部署。  
  
由于是未授权的上传点。也算是前台rce了～～～  
  
文章声明：  
该工具、教程仅供学习参考，请勿非法使用。  
否则与作者无关！  
  
