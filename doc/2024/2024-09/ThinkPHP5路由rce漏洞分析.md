#  ThinkPHP5路由rce漏洞分析   
原创 阅  SecNL安全团队   2024-09-15 09:33  
  
ThinkPHP5路由rce漏洞分析  
  
  
  
使用的版本是tp5.0.18  
  
https://github.com/top-think/framework/releases/tag/v5.0.18  
  
https://github.com/top-think/think/releases/tag/v5.0.18  
  
路由分析  
  
从index.php开始路由分析，用动态调试的方法来进行路由分析  
  
首先是看index.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCF3Bxg2zBRE2BHHVORpxV8C3rkeILOyKv76Hl5DwRBxQJjTic1bXSibkYQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
再跟到start.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCF8cbmMn1RATrTo8BeSOnMTaJOvU1zAXdoqyy9sib2Lzz8o70RKO6wlTA/640?wx_fmt=png&from=appmsg "")  
  
  
  
补充一下：App通常是应用程序的主要入口类，run方法通常负责启动应用程序的生命周期。这包括初始化配置、设置路由、加载必要的服务和中间件等。send方法通常用于发送最终的响应到客户端。在大多数Web应用框架中，它会输出HTTP响应内容，如HTML、JSON、文件等，并合理设置HTTP头信息。  
  
总的来说就是结合起来，这行代码可以解释为，应用通过   
App::run()  
 启动整个应用程序，并在所有处理完成后，通过   
send()  
 方法发送结果到客户端。  
**所以要分析路由的话，我们要跟到run里面去看。**  
  
跟到run里面，这里面就是检测请求的地方了，可以看到这里的输入都有request  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFd7QBQmlaVzDVZkHZwNt3yoJibicmZGiclWUtsfz0wejz8qTibyPFfz3Pgw/640?wx_fmt=png&from=appmsg "")  
  
  
  
这里我就不放截图了，放了就过于冗长了，简单审计一下前面的东西。然后直接到重要的这个地方，routeCheck这里就是检测路由的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFfuXJuedLg9dfvoXhlic9XKbUORkHxbW76dEEW9RmXeTsY4sfygYVeaw/640?wx_fmt=png&from=appmsg "")  
  
  
  
因为这个dispatch为null，那我们肯定是可以进入这个逻辑的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFExNoCMTYc9yQzUibQsQA7a98iaSKWffaxP5teHIrXTUrT6iaGImJCQ03A/640?wx_fmt=png&from=appmsg "")  
  
  
  
跟进routecheck  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFlAYwb9iaaGdDSFFIB7yEpDOL845pPfhKqJ5ic0XIia5iaGuLsDbWm1oQdQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
可以看到我们的请求路径就在这里被从request请求里面取出来，然后传给了path变量。  
  
  
然后第二步是从config里面取了个符号  
/  
出来，用来后面分割我们的路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFqnC9WF5JTB2T6D3vjOTP2bc0EoomCeD1qMCDDXNR9H6hmwGPXUhElA/640?wx_fmt=png&from=appmsg "")  
  
  
  
下一步：检测路由，如果  
self::$routeCheck  
是null，则从config里面读取配置，默认就为true  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFSrVpuovwcGQGDFylgzVEbzEgV4BmHb529IdMPryQZy4QHa9JJZh4pg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFSMkRI9r7ibwMen0QGLK4FLUsDI56hOqJfCQ9MlibCqqnQIiaPAtsf44iaA/640?wx_fmt=png&from=appmsg "")  
  
  
  
然后看有没有路由的缓存文件，有的话，就包含；没有的话，就从配置里面读路由文件的路径，然后包含。简单的讲，就是去包含一个router.php的文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFyMHlqTuOavHf4kjvrl5d94rG56MovUicjuqCISUia9bg5ibJq8sic9Lh1A/640?wx_fmt=png&from=appmsg "")  
  
  
  
然后看有没有路由的缓存文件，有的话，就包含；没有的话，就从配置里面读路由文件的路径，然后包含。简单的讲，就是去包含一个router.php的文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCF0owIichvDcficj2AEg677mBOcw1pDvDTCRPC7SiceppcQ1qAF7mp9mGiaQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
这里的Route::check简单的讲就是看你的url是不是匹配到了router.php里面的路由，如果没有匹配到，就走  
解析模块/控制器/操作/参数  
的逻辑去检测url，匹配到了则就这样。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFdnVIQ8XiclS8vJg3ticSD0M0FibrLDy17CiaHyXOBZzR33ORHtQ6TrRSibQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCF6868wKSnibdWrz0a7Diask45ib3azXRnicagfCaJj6r2VD6GSFLHjAKS8Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
我们这里返回的是false显然是不走这个逻辑的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFH76Z2pdmzD7Ct9XQZtwI8u3kYQ7fDlD9vtnENjyn9g4kclKWWdMukA/640?wx_fmt=png&from=appmsg "")  
  
  
  
最后就走到常规的url的检测逻辑了，也就是最后一步。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFauHA8uUZSQIplDocJSPl5PDxSGUpR8Z4liagta3qu0EtbFAuwN9rCLQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
我们跟进  
Route::parseUrl  
去看一看。  
  
  
跟进去之前我们先理一理之前的逻辑  
  
从  
index.php  
->  
start.php  
->  
App::run()  
->  
App中的self::routeCheck  
->  
输入的path没在router.php设置的路由中匹配到  
->  
最后进入routeCheck中的Route::parseUrl操作  
  
好现在我们进入  
Route::parseUrl  
看一下。  
  
看是不是绑定了路由，没绑定就不过第一个逻辑，我们这里没绑定就不会过这个逻辑  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFbiaoomq4RLwjZn2CduKkCar71mkHq9iavl6mSoCWiaicTnFXExEia3sUOFw/640?wx_fmt=png&from=appmsg "")  
  
  
  
下面这里就把url分割开来了，存在path中按竖线分成了数组中的元素。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFWibNbM1YnmLTfKy0uLA6XFbGpcgib9HftS11ZqicqRicibBVJXTsYL31MrA/640?wx_fmt=png&from=appmsg "")  
  
  
  
检测到path存在值之后，就进入下面的解析路由的模块了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFJY9hUFYoOLiaDQQJD7WVgKAet1YCAd0RppCsvdtYWQ1UXQ9OudGRlTg/640?wx_fmt=png&from=appmsg "")  
  
  
  
然后看是否支持多模块，默认支持，则从path中删除第一个元素，然后将删除的第一个元素传输给module。  
  
module下面的if中$autoSearch是从config里取出的，看设置是否自动搜索控制器，默认为false。所以下面这个if不经过。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFIjxfAHVDCZaiaSuSEegXjnoyn7rBbmxXDupZQfHxHzeibQibn4J6EShlA/640?wx_fmt=png&from=appmsg "")  
  
  
  
走到下面的else里就是挨个从path数组中取出控制器controller，以及操作action，以及操作后面跟的参数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFMyicGqS30GZGJHb76kcgDB5IWiaWlW224VxqRV9WUe7jNgMVzicbhBWDg/640?wx_fmt=png&from=appmsg "")  
  
  
  
最后两个if逻辑，第一个是看之前绑定的bind里面有没有mudule或者mudule是不是空，如果满足一个条件 -> 则会按照controller/action的方式去看之前有没有绑定。通过这样做，可以确保当前请求的URL不会与已定义的路由规则发生冲突，防止重复定义导致路由处理混乱。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFCAjNoyzeLsKOpznpwibFPdj8OgnCrj70Lb01dAy3gjYY8YwgvkuknEw/640?wx_fmt=png&from=appmsg "")  
  
  
  
这两个if逻辑正常访问都是直接过，然后最后就return了一个如下图所示的数组出去  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFfAOkP2DEJ7te91m2k6iaZQ57RXEuztzKVCNsSlWSxzLKp98RbsxhGJQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFpbCDmVPvKKgGXdoWgviaOaYJkfp5FYeL2dctapVibzwdrrdp8JNUPn4g/640?wx_fmt=png&from=appmsg "")  
  
  
  
再理一下，从index.php->start.php->App::run()->App中的self::routeCheck->输入的path没在router.php设置的路由中匹配到->最后进入routeCheck中的Route::parseUrl操作->parseurl看是否有重复绑定，没有则返回 模块/控制器/操作 的一个数组   
  
最后数组返回出来就简单点看看，只看关键的地方，去看一下在哪里调用类的  
  
回到我们最开始的App::run()这里，通过动态调试，得知了最终调用类和方法的地方在这里，exec  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFQ9fZqXPQfjuIUVEO9nMcUhZkhedmluWDVO614jU1R55jGogL9ychWQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
exec -> module  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFJ5OBD4eVFnGYBwicpy2icrD1WvfibDVs9icHO1Obk0K9shuxtZmplYHYew/640?wx_fmt=png&from=appmsg "")  
  
  
  
exec -> module -> Loader::controller  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCF0fWou8jMW06sE1Ptaib4F4dYqCy6BKwVVD4VNtngXyGlWt4gDoibMgNQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
exec -> module -> Loader::controller ->class_exists  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFyqWWvh1Sx2kCcPwG3qSGiatLJnBwzWG4odia1akrQ5ImD8Sm3K0ia5LKw/640?wx_fmt=png&from=appmsg "")  
  
  
  
exec -> module -> Loader::controller ->class_exists ->存在就__include_file(看了下就是include)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFLbxoBBIA9805kA9SiavWbaSdEdZtChwD2eMqsBeQ4icqZuCjwUwJ3mEw/640?wx_fmt=png&from=appmsg "")  
  
  
  
exec -> module -> Loader::controller ->class_exists ->存在就__include_file(看了下就是include) -> 刚刚返回true后回到controller 去调用这个class  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCF9Hcr8FWs6XMnkH3uhnO3UTQWfiaCYlBuPdQyZzszwSXbca4ibqlTVa8A/640?wx_fmt=png&from=appmsg "")  
  
  
  
exec -> module -> Loader::controller ->class_exists ->存在就__include_file(看了下就是include) -> 刚刚返回true后回到controller 去调用这个class ->回到module用is_callable看hello方法能否调用，能调用就直接用反射去调用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFuSjcpFypVzRGTdtZM3C9cmZSEKCuyfO569e72VGh80OYaMP9YH5bSg/640?wx_fmt=png&from=appmsg "")  
  
  
  
最后App.php:343, think\App::invokeMethod()这里用反射去调用了我们传入的类的方法，而类就是之前获取到的index类。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFs2xCBAshVdzspNAMoJj8nDs1IiaWzUiatR3Jw2vFy3cL3ESGeV0zwXLg/640?wx_fmt=png&from=appmsg "")  
  
  
  
最后总结一下整个流程就是 index.php->start.php->App::run()->App中的self::routeCheck->输入的path没在router.php设置的路由中匹配到->最后进入routeCheck中的Route::parseUrl操作->parseurl看是否有重复绑定，没有则返回 模块/控制器/操作 的一个数组  -> exec -> module ->Loader::controller ->class_exists ->存在就__include_file(看了下就是include) -> 刚刚返回true后回到controller 去调用这个class ->回到module用is_callable看hello方法能否调用，能调用就直接用反射去调用 -> App.php:331, think\App::invokeMethod()用反射动态调用构造好的类的路径去调用方法。  
  
简单的讲：如果有controller就直接调用，如果controller传入的方法能调用，就调用。  
  
漏洞点就出来了，如果能调用任意的类，执行任意的方法，就可以rce了，或者就算不是任意类，只要找到一个其他能rce到类就行。  
  
  
漏洞分析  
  
我们回到刚才调用类的地方，如果我们直接传入一个任意类，程序就会默认的给我们拼接为app\index\controller\Evil。这里我们仔细看可以看到，controller传入参数的地方，他其实并没有传入module，只传入了controller也就是我们的Evil类。也就是说路径前面的controller肯定是在这里面自己默认加进去的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFakQibFJoianBWCDvERUYLPHc8iatQwpaxJlDCRAmR3NTplXDrFIMhHyTg/640?wx_fmt=png&from=appmsg "")  
  
  
  
这样就导致我们，只能进入controller文件夹去调用类，而我们需要调用任意的类，就要从这个构造class变量的方法去入手了。也就是getModuleAndClass这个地方，跟进去看一眼，代码分析我就直接写在注释里面。  
```
```  
  
可以看到如果name带有\符号那就回直接返回。现在我们来看看  
  
**兼容模式**  
  
  
如果我们直接访问http://127.0.0.1/public/index.php/\index/\evil/\hello的话，http协议就会给我们转义掉了。那就没办法在类名中加入反斜线了，这时候我们就要想到thinkphp的兼容模式。  
  
这里就简单介绍一下，这个兼容模式是默认开启的，并且参数默认也是s。  
  
其作用就是假如访问http://127.0.0.1/public/index.php?s=index/evil/hello，它的效果和http://127.0.0.1/public/index.php/index/evil/hello的效果是一样。用兼容模式去访问的话，就不会被http转义掉我们的反斜线了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFRZnXuNZtNK9WZ41CkcSagDlEFaRq8TuHic5H4IQ3HzormGmrC82ngjg/640?wx_fmt=png&from=appmsg "")  
  
  
  
如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCF2nPJLfWtfhIsP5icfn2jfIeqmKQOJ7WBOaqTJNuqd38Tc9kW0r9yOyw/640?wx_fmt=png&from=appmsg "")  
  
  
  
现在我们再去在参数中加入反斜线  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFQhdykt6WNHlCPhAlzNINsqOoS4mhUzcznX93icbQZ9bRJNgEf5fgfbQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
成功把app\index\controller\Evil变成\evil了。  
  
  
继续  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFE8ujuk2Lb8U67QrdGBDUryaRRrRphIEjRc4icxWdE5r4bFpviaxLOKOg/640?wx_fmt=png&from=appmsg "")  
  
  
  
刚才说到，我们已经成功把class变成\evil了。就是说我们原来只能去controller里面的东西，现在我们已经绕出来了。  
  
为了包含我们想要的rce的类，这里要说一说php反射的一个点。  
**php反射只能操作已经声明的类。这是因为反射是基于运行时的元数据来工作的，如果类尚未声明，自然不存在元数据供反射机制使用。**  
  
这里我们就可以在idea的控制台使用  
get_declared_classes()  
来获取所有已经声明的类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFIr6vMyEltaCg0OLGbZoR9PHDKichYGQhcmW8icwoW0YmbfppBkdfRxvQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFkvygyia74e7LNs45cMA7wWA3MbctAibsE13cRJb2yunFajbibFZOvA4mA/640?wx_fmt=png&from=appmsg "")  
  
  
  
由于是分析漏洞，我们就不一个一个找了，看这里的一个  
https://github.com/Mochazz/ThinkPHP-Vuln/blob/master/ThinkPHP5/ThinkPHP5%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%E4%B9%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C9.md  
  
payload里面用的类来进行分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFVKaHWZoxNyNxWC3apKEvxRcZia5L2hLOKMsCOs427QvfFMDLjen85gw/640?wx_fmt=png&from=appmsg "")  
  
  
```
```  
  
我们就看最后一个payload吧..因为我试了下上面的好像在这个版本都不成功。  
  
可以看到确实是有这个类的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFOGmLsRuUWCXfYXq2wE6omsdcDKWNJKGuA4DqaicjCF4m8TVxVjtJ6Lw/640?wx_fmt=png&from=appmsg "")  
  
  
  
找到\think\app/invokefunction。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFpku5RgcIw9vbI1jNlMnT3nYVbbAUWOFKHOQ89ZIm7MmOk4aeafUzcA/640?wx_fmt=png&from=appmsg "")  
  
  
```
```  
  
简单的讲就是传入一个$function是函数名，另一个数组里面就是函数的参数。所以到这里就很清晰了。  
  
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=calc  
  
就是用  
call_user_func_array  
去执行  
calc  
来弹计算器就行了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ny8tG5SicPMlEwBfCaWg71WOUHcN4zNCFTgFm2DTlqbU2iblJHZDtmhsbSsOf0IUIzQGFF9XT1dZDGfnxYoB5jHw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
