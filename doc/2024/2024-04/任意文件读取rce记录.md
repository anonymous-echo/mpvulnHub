#  任意文件读取rce记录   
中铁13层打工人  迪哥讲事   2024-04-25 21:39  
  
**1.跨目录上传**  
  
对某系统进行测试时，发现有一处上传附件的功能，常规上传个文件试试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVt4ibURlINlFcCvUFXIJNBrtDvNtAW6clibCrzU6oErPJD07DMc3CJd9g/640?wx_fmt=png&wxfrom=13 "")  
  
  
发现返回包返回了重命名后的文件名称和系统的绝对路径  
  
  
继续看上传的文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVXicmSBs6UfITRxiaLbHT0rTibIacyHibQACLCk1iceNghwIdGQpg5t0F5rw/640?wx_fmt=png&wxfrom=13 "")  
  
  
只  
有一个预览的功能，访问直接下载该文件，  
并没有什么用，  
请求链接为  
```
DownloadServlet?type=W***J&filename=QQ%E5%9B%BE%E7%89%8720230414145425.jpg&pyName=9be6c164-d5a9-4a1e-a555-139ec1ce383d.jpg
```  
  
  
  
  
回头仔细看上传的数据包，发现上传的参数type的值返回在了系统的绝对路径中，猜测type的值即为上传的文件夹，将type改成1尝试，印证了猜想，且是可以直接上传jsp的！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVItUcmQ4DxzLVE1mMtr6rqoWYrnucwtO9XTVfGa9exsUiceD67GlicVhA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
既然上传文件参数可控，尝试使用../看是否可以跨目录上传，发现也是可以的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVgJJj6dAiaH4UUbxNo7ysJU5v0qeK2zvKGqljJWPIbcBjkibc7zoFSQzw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
至此得到一个上传路径可控的有效上传点，且通过上传返回的绝对路径知道了当前的user名称（这个后面很关键）。  
  
  
那么接下来的思路就是寻找系统的web路径，直接上传脚本getshell。尝试了一些常用的手法例如构造报错等均未找到目标，尬住了一会儿后，想到了之前的跨目录上传，既然上传处可以使用../进行跨目录，那么上传后的预览处呢？  
  
  
**2.任意文件读取**  
  
回到刚才的上传预览处  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVTKFEUicibianThHswKoXYiamh1uSzvgibUXNMU7MRQWb4jw3FjdjXmHoCMg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
将预览功能处的请求链接  
中的filename与pyname进行构造尝试，果不其然，发现一处任意文件读取  
```
DownloadServlet?type=W***J&filename=QQ%E5%9B%BE%E7%89%8720230414145425.jpg&pyName=9be6c164-d5a9-4a1e-a555-139ec1ce383d.jpg
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVTfyC7MvU2mMJibtn48h1KUBTOibnLgYltDW2LGqv1DbibYRMROzQ6qAIg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
得到任意文件读取后可以通过读取中间件的默认配置文件寻找更多信息，例如  
  
  
**tomcat**  
```
/usr/local/tomcat(tomcat-1.1.1(具体版本号))/conf/tomcat-users.xml
/usr/local/tomcat(tomcat-1.1.1(具体版本号))/bin/catalina.sh(其中日志的配置路径)
```  
  
  
**apache**  
```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access_log
/etc/httpd/logs/access_log
/etc/httpd/logs/error_log
/etc/httpd/logs/error.log
```  
  
  
**nginx**  
```
/var/log/nginx(nginx-1.1.1(具体版本号))/access.log
/var/log/nginx(nginx-1.1.1(具体版本号))/error.log
/usr/local/var/log/nginx(nginx-1.1.1(具体版本号))/access.log
/usr/local/nginx(nginx-1.1.1(具体版本号))/logs
/etc/nginx(nginx-1.1.1(具体版本号))/nginx.conf
```  
  
  
通过旁站的其他端口的web指纹，发现使用的是tomcat  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVzFQAGRcRyIMkurFicyWMbKj5p1wpr5Pv5qdwOQAUh6lIWcuvkHMVQSQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
直接尝试读取tomcat的默认配置文件，均失败：）  
  
  
接着尝试读取操作系统的默认路径，linux下常用路径如下  
```
/etc/passwd                     账户信息
/etc/shadow                     账户密码文件
/etc/my.cnf                     mysql配置文件
/root/.ssh/id_rsa               ssh-rsa私钥
/etc/redhat-release             系统版本 
/root/.bash_history             用户历史命令记录文件
/home/user/.bash_history        特定用户的历史命令记录文件
/root/.mysql_history            mysql历史命令记录文件
/var/lib/mlocate/mlocate.db     全文件路径
/proc/net/fib_trie              内网IP
/proc/self/environ              环境变量
/proc/self/loginuid             当前用户uid
```  
  
  
最终通过/home/user/.bash_history中成功找到了tomcat的web路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVXXCRfXOicYVaJbGKnkVaSibMsGuwE3qzicBCP0jet4anoh1rQGQBrBEsA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**3.getshell**  
  
万事具备，直接上传至根目录下，访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVaaVjPgQHsCQgsAicP2XEUp9uULtGIqKh4xhnVcZOypXJ5G1p4dRhYcg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
根目录下不解析，直接跳转到了登录页面，但是可以看到跳转目录携带了我们访问的jsp。  
  
  
这种情况下，有账号的话(本系统提供了注册功能)，直接登录后访问即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVTZtxzEtvureL7OKpmh7L7gXw3W6Q9boIaXPlKuMPLficJzU58j4HAyA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**4.一些拓展**  
  
上述的情况都是登录后测试的，如果上传点是fuzz出来的，没有目标系统的账号，也可以采取如下几种方案。  
- 1.尝试直接上传至系统的静态目录，例如系统自动加载的js文件的目录。  
  
- 2.尝试绕过fillter的鉴权，一般从fillter对目录的白名单或是文件后缀的白名单两个角度绕过入手。  
  
附一些实战的案例。  
  
  
**目录白名单绕过**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVqqqTH32AhSKxdG6GnaU2rCygaEpTacpmcWJICN7OibSwb5JT6iaAagJw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVkn9tOwgoiawvvk3BQDtpiaD68gCc5AibmAmsJfliagVsiawwAsYpM7IqP7Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**文件后缀白名单绕过**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVq2St5D3c7YUau10ZsJaZbibufU4QVlKsCic0NsAju3icGRbcT3vziaz76A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVzsNLOCot89a4D4LSoGAWQOrKSyBfQOdbLaOdoA5gCGLCqMLibGUjKNw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**其他情况绕过**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVhPCaiaIMZeQhTwwV3MqWeicHcxiaicibahaKIiczccgW7icZwGrwYFn0cAcdQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVQj99z6N9FU37sGEdsRUcwq2JibByn3y8QAEyymwGtDUrhcic7icL8iaMiaA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
3.寻找其他的web可以直接访问且知道路径的目录  
  
**例如本案例中的**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVNm4AibHadebYp5Ania8CmIHmNN2jbC1P2MTthe3IhZ5NdwJ56suibbQKQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVs5P6hszS0icibgIYJlciaibnH7TG1yznua5oY4TBKHMI5qOcMoDaHxh0VA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
直接构造上传  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenV8hePgmKkJ5FJ48XYmqQZSuXQQQKgxkfCsaRpmAS5kgPeKTmocc8lpg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
浏览器访问，成功rce  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/XOPdGZ2MYOfR8FyaBtPibBP6lblrkmenVvB5Q2CznYZ6hjqN8qUrnNVjbuq01JHoIXYXW92HTp6hzDGdM4YAoicg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
原文: https://forum.butian.net/share/2350  
  
