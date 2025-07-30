#  Thinkphp3文件包含(CNVD-2024-39045)   
 摸鱼Sec   2024-11-12 21:37  
  
# 声明：请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。  
#   
# 一.基础信息    
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="text-indent: 0em;line-height: normal;"><span style=" color: rgb(217, 33, 66); ; " data-darkreader-inline-color=""><strong><span style="font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;">一个月前发了一个tp5的鸡肋漏洞,限制必须只能windows系统，这里的tp3就不限制系统，但是还是存在一定的鸡肋，具体看下面文章吧，在7月份写文章的时候那天晚上喝酒了,可能会有错别字或者不通顺的地方，哈哈也是文化水平有限，过一两个月我会发禅道的前台rce，本想着不公开的但是在朋友那块得知貌似hw的时候见过眼熟这里我也不知真假，最近也一直在学车考驾照真是难死我了，希望在年前能拿到驾照。</span></strong></span></p><p style="margin-top: 15.6pt;margin-bottom: 2.5pt;text-align: left;margin-left: 0pt;text-indent: 0em;line-height: normal;"><span style=" color: rgb(217, 33, 66); ; " data-darkreader-inline-color=""><strong><span style="font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;">time 7.15</span></strong></span></p><p style="margin-top: 15.6pt;margin-bottom: 2.5pt;text-align: left;margin-left: 0pt;text-indent: 0em;line-height: normal;"><span style=" color: rgb(217, 33, 66); ; " data-darkreader-inline-color=""><strong><span style="font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;">测试版本Version: 3.2.5</span></strong></span></p><p style="margin-top: 15.6pt;margin-bottom: 2.5pt;text-align: left;margin-left: 0pt;text-indent: 0em;line-height: normal;"><span style=" color: rgb(217, 33, 66); ; " data-darkreader-inline-color=""><strong><span style="font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;">php: 7.3.4</span></strong></span></p><p style="margin-top: 15.6pt;margin-bottom: 2.5pt;text-align: left;margin-left: 0pt;text-indent: 0em;line-height: normal;"><span style=" color: rgb(217, 33, 66); ; " data-darkreader-inline-color=""><strong><span style="font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;">影响范围：&lt;= 3.2.5</span></strong></span></p><p style="margin-top: 15.6pt;margin-bottom: 2.5pt;text-align: left;margin-left: 0pt;text-indent: 0em;line-height: normal;"><span style=" color: rgb(217, 33, 66); ; " data-darkreader-inline-color=""><strong><span style="font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;">漏洞利用poc: index.php?m=Home&amp;c=index&amp;a=../../../../../文件名</span></strong></span></p><p style="text-indent: 0em;line-height: normal;"><span style=" color: rgb(217, 33, 66); ; " data-darkreader-inline-color=""><strong><span style=" color: rgb(217, 33, 66);font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">调用堆栈：</span></strong></span></p></td></tr></tbody></table>```
File.class.php:88, Think\Storage\Driver\File->load()            
Storage.class.php:41, call_user_func_array:{D:\phpStudy\WWW\thinkphp-3.2.5\ThinkPHP\Library\Think\Storage.class.php:41}()            
Storage.class.php:41, Think\Storage::__callStatic()            
Template.class.php:91, Think\Storage::load()            
Template.class.php:91, Think\Template->fetch()            
ParseTemplateBehavior.class.php:38, Behavior\ParseTemplateBehavior->run()            
Hook.class.php:131, Think\Hook::exec()            
Hook.class.php:99, Think\Hook::listen()            
View.class.php:155, Think\View->fetch()            
View.class.php:77, Think\View->display()            
Controller.class.php:62, Home\Controller\IndexController->display()            
Controller.class.php:185, Home\Controller\IndexController->__call()            
App.class.php:118, ReflectionMethod->invokeArgs()            
App.class.php:118, Think\App::exec()            
App.class.php:214, Think\App::run()            
Think.class.php:139, Think\Think::start()            
ThinkPHP.php:100, require()            
index.php:26, {main}()
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZdS1r2ibo3ZKs04Lq4SaAaP9PRDKOlrWoYiaC9PhSKdlBvHGWnRpcLESg/640?wx_fmt=png "")  
  
  
      
#   
#   
# 二.审计过程    
### 1.1: 路由分析    
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><strong><span style="mso-bookmark:ude238d6e;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">在Thinkphp5中使用使用最多的就两种方式，但在Thinkphp3中而是三种</span></span></strong><span style="mso-bookmark:ude238d6e;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">：</span></span><span style="mso-bookmark:ude238d6e;"><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:Times New Roman;font-variant:normal;text-transform:none;"></span></span><p style="margin-top:15.6pt;mso-para-margin-top:1.0gd;margin-bottom:2.5pt;text-align:left;margin-left:0.0pt;line-height:150%;"><span style="mso-bookmark:ude238d6e;"></span><span style="mso-bookmark:u0a3f3361;"></span><span style="mso-bookmark:u0a3f3361;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 255);font-weight: normal;font-style: normal;text-decoration: none; ; " data-darkreader-inline-color="">http://127.0.0.1/index.php?m=模块&amp;c=控制器&amp;a=方法</span></span><span style="mso-bookmark:u0a3f3361;"><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:Times New Roman;font-variant:normal;text-transform:none;"></span></span></p><p style="margin-top:15.6pt;mso-para-margin-top:1.0gd;margin-bottom:2.5pt;text-align:left;margin-left:0.0pt;line-height:150%;"><span style="mso-bookmark:u0a3f3361;"></span><span style="mso-bookmark:u0520ae40;"></span><span style="mso-bookmark:u0520ae40;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 255);font-weight: normal;font-style: normal;text-decoration: none; ; " data-darkreader-inline-color="">http://127.0.0.1/index.php?s=模块/控制器/方法</span></span><span style="mso-bookmark:u0520ae40;"><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:Times New Roman;font-variant:normal;text-transform:none;"></span></span></p><span style="mso-bookmark:u0520ae40;"></span><strong><span style="mso-bookmark:ubf3ec4d3;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">上面是可以在文档中查到的，下面分析在代码中的实现。</span></span></strong><span style="mso-bookmark:ubf3ec4d3;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color=""></span></span></td></tr></tbody></table>  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZToqNa6ljOXrBCeDl8ueCAibMTP2X1w1T9Piciab8Irk9ib0cznib5LDcrtw/640?wx_fmt=png "")  
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">常量的话没遇危险点不用看，ThinkPHP.php又定义了许多常量，在最后面执行了Think::start()，</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">给进去看看弄了啥，这里面也就是加载了一些配置文件都是写死的没法利用，在这个方法最后面执行了App下面的run方法，但是这块存在三个App类具体是哪一个，可以看到下面61行的时候存在一个inculde</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">其实下面有好几个但是大致看一下注释就知道是这了，print_r($mode[&#39;core&#39;]); 发现执行的是</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">ThinkPHP/Library/Think/App.class.php。</span></strong></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZP4gQfOiczDSh4cQeSo0yWn8DSeVp4XJDIq4yjQ0lYFm0DtJkTflegzA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZGJd24KPtXhs8zN1lbSPWyQ8RfmZCJhuPVY27tMpXnN3DHriadO8bnrg/640?wx_fmt=other&from=appmsg "")  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><strong><span style="mso-bookmark:u0a2a176e;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">跟进去看看干了什么，虽然上面存在很多inculde但是没有一个我们能控制的，所以接着看，下面就是执行到了run()</span></span></strong></td></tr></tbody></table>```
public static function run()            
{            
    // 加载动态应用公共文件和配置            
    load_ext_file(COMMON_PATH);            
    // 应用初始化标签            
    Hook::listen('app_init');            
    App::init();            
    // 应用开始标签            
    Hook::listen('app_begin');            
    // Session初始化            
    if (!IS_CLI) {            
        session(C('SESSION_OPTIONS'));            
    }            
    // 记录应用初始化时间            
    G('initTime');            
    App::exec();            
    // 应用结束标签            
    Hook::listen('app_end');            
    return;            
}            
其中load_ext_file(COMMON_PATH); COMMON_PATH是/Application/Common/ ，load_ext_file            
方法我看了一下其实啥也没干看下图C('LOAD_EXT_FILE')是空的导致两个条件都进不去。
Hook::listen('app_init');也差不多，对于审计来说确实意义不大。
重点：App::init();看下面代码
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZTlRukL0fYA9KJkO1xaGRkpPYCxeOx5OqiciaflcIibaGa5MUPsXdek5lA/640?wx_fmt=png "")  
  
  
      
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><strong><span style="mso-bookmark:u60c47d0e;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">刚开始写了一些常量$_SERVER[&#39;REQUEST_TIME&#39;]
 
时间戳，$_SERVER[&#39;REQUEST_METHOD&#39;]请求类型，目前看的话没啥东西，直接看Dispatcher::dispatch();但是Dispatcher类又存在三个类和同样的方法具体是哪一个，可以看找App类的图这块我就不在截图了哈。</span></span></strong><span style="mso-bookmark:u60c47d0e;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color=""></span></span><br/></td></tr></tbody></table>```
public static function init()            
{            
    // 日志目录转换为绝对路径 默认情况下存储到公共模块下面            
    C('LOG_PATH', realpath(LOG_PATH) . '/Common/');            
           
    // 定义当前请求的系统常量            
    define('NOW_TIME', $_SERVER['REQUEST_TIME']);            
    define('REQUEST_METHOD', $_SERVER['REQUEST_METHOD']);            
    define('IS_GET', REQUEST_METHOD == 'GET' ? true : false);            
    define('IS_POST', REQUEST_METHOD == 'POST' ? true : false);            
    define('IS_PUT', REQUEST_METHOD == 'PUT' ? true : false);            
    define('IS_DELETE', REQUEST_METHOD == 'DELETE' ? true : false);            
           
    // URL调度            
    Dispatcher::dispatch();            
           
    if (C('REQUEST_VARS_FILTER')) {            
        // 全局安全过滤            
        array_walk_recursive($_GET, 'think_filter');            
        array_walk_recursive($_POST, 'think_filter');            
        array_walk_recursive($_REQUEST, 'think_filter');            
    }            
           
    // URL调度结束标签            
    Hook::listen('url_dispatch');            
           
    define('IS_AJAX', ((isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') || !empty($_POST[C('VAR_AJAX_SUBMIT')]) || !empty($_GET[C('VAR_AJAX_SUBMIT')])) ? true : false);            
           
    // TMPL_EXCEPTION_FILE 改为绝对地址            
    C('TMPL_EXCEPTION_FILE', realpath(C('TMPL_EXCEPTION_FILE')));            
    return;            
}            
```  
<table><tbody><tr><td width="558.3333333333334" valign="top" style="word-break: break-all;"><strong><span style="mso-bookmark:u1cf651b8;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">看到这呢根据注释已经可以看出找到第二种方式了，$varPath输出一下其实就是s,然后我们一直看到</span></span><span style="mso-bookmark:u1cf651b8;"><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:Times New Roman;font-variant:normal;text-transform:none;"></span></span>    <span style="mso-bookmark:u1cf651b8;"></span><span style="mso-bookmark:uc06280e7;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">145行的时候执行了define(&#39;MODULE_NAME&#39;, self::getModule($paths));其中$paths给到MODULE_NAME这个常量，跟进去看看，为啥看这个方法因为我在这个下面看到一个if用到了这个常量可以看下图。</span></span></strong><span style="mso-bookmark:uc06280e7;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color=""></span></span></td></tr></tbody></table>  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZScc4JZPVxEU2ODGc5JtTKPDSkOpOp6KycT4B4P4Rvl0aT6l5By4hlA/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZryTyicLG0GVprwWOrY32zEL5DXccnq8KtKmicIdWFgXeYS56MBdO52Wg/640?wx_fmt=png "")  
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><strong><span style="mso-bookmark:u1a97629f;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">第一个if输出一下就知道了，第2个$paths本身就是空，第三个一样的，所以他只能走到else，$var输出是m,$module获取了GET的参数在进行了销毁，第四个直接过，第五个C(&#39;URL_MODULE_MAP&#39;)是空的，最后直接return返回$module了，然后返回到Dispatcher类，is_dir(APP_PATH
 . MODULE_NAME)</span></span><span style="mso-bookmark:u1a97629f;"><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:Times New Roman;font-variant:normal;text-transform:none;"></span></span>    <span style="mso-bookmark:u1a97629f;"></span><span style="mso-bookmark:u393579f9;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">MODULE_NAME目前是我们能控制的，所以必须走下去不然程序直接就结束了，APP_PATH是Application目录这个目录下面有模块Home，其实大致也就清楚了这是第一种路由，走进去之后又是一堆include但是没有能控制的，唯独load_ext_file(MODULE_PATH);可以控制但是上面说过load_ext_file这个方法啥也没干，走到218行和219行进去之后也验证了我们的猜想，代码我就不解释了和模块代码大差不差，下面是图。</span></span></strong><span style="mso-bookmark:u393579f9;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color=""></span></span></td></tr></tbody></table>  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZD6g2YfR73dtslWkvib3FzgsxegSozOHdibVGiaFD0GKV8kWUlH85o5cjg/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZUXTBKwC7CMZnaibNoricRWX5RBHxygFoZ64cehjVjFTE8jb8EdqR6jUQ/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZdcVsNHpTsZfNWA2QZPggsPCvjMS21l1JQsuia8yGFaXJTxMBBPrSWhQ/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1Zy09IQPphpwGibQVla4W7QO4WJGw7tzvRiazBbJr2ib6V1MAwU5tYbdtWg/640?wx_fmt=other&from=appmsg "")  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><strong><span style="mso-bookmark:u48e591e0;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">之后就是执行了一些对本次漏洞没太大意义的东西就不说了，回到init后面也是没啥意义的东西。</span></span></strong><span style="mso-bookmark:u48e591e0;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color=""></span></span></td></tr></tbody></table>  
  
### 1.2：漏洞执行过程   
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><strong><span style="font-size: 14px;">前</span></strong><span style="font-size: 14px;"><strong>面分析了路由下面我们看看这次的文件包含如何产生的，回到run()方法，215行执行了App::exec();跟进去看看，CONTROLLER_NAME我么再熟悉不过了不就是刚才c的常量吗 /^[A-Za-z](\/|\w)*$/  必须是这个正则的内容 不是的话$module是false,就会执行到95行 exit就结束了，所以我们正常输入其中几个if大家输出一下就知道了我就不废话了，会走到else里面 这个方法不就是控制器的意思吗跟进去看看controller。</strong></span><br/></td></tr></tbody></table>  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZZxaicHRES0vyibCqiazNfVugtNnCFtjE6pjoISR0jcRUJDW09nh7Vmbxw/640?wx_fmt=png "")  
  
  
```
function controller($name, $path = '')
{
    $layer = C('DEFAULT_C_LAYER');
    if (!C('APP_USE_NAMESPACE')) {
        $class = parse_name($name, 1) . $layer;
        import(MODULE_NAME . '/' . $layer . '/' . $class);
    } else {
        $class = ($path ? basename(ADDON_PATH) . '\\' . $path : MODULE_NAME) . '\\' . $layer;
        $array = explode('/', $name);
        foreach ($array as $name) {
            $class .= '\\' . parse_name($name, 1);
        }
        $class .= $layer;
    }
    if (class_exists($class)) {
        return new $class();
    } else {
        return false;
    }
}
```  
```
$class = ($path ? basename(ADDON_PATH) . '\\'. $path : MODULE_NAME) . '\\' . $layer;
    $array = explode('/', $name);
    foreach ($array as $name) {
        $class .= '\\' . parse_name($name, 1);
    }
    $class .= $layer;
}
if (class_exists($class)) {
    return new $class();
上面的是重点,其他的不用看，MODULE_NAME常量是m $layer是controller $name就是刚开始传过来的常量 CONTROLLER_NAME也就是c
(class_exists($class)查看我们输出的类存不存在，存在直接new不存在就false。
下面就是109行ACTION_NAME是a，给到$action，113行进去看看，里面其实做了一个反射，主要看
117行通过反射动态执行了一个__call魔术方法，但是要执行到116行必须要存在一个错误，所以还是要进去看看113行。
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZQPaHYY9UJhqLLgpVyPmFBAcBe2S1Pm3J4G26SvVN7gQ6X7r3SBJChg/640?wx_fmt=png "")  
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">$action是我们能控制的a,只要不是这个正则里面的就能执行到116行了$module也就是我们的类。</span></strong></p></td></tr></tbody></table>  
  
   
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZeibI77g0as9ibKtNZg4LkibZMFpuia3eBuDecKshuOagUR4rfS0yFxV4BQ/640?wx_fmt=png "")  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">那么Application/Home/Controller/IndexController.class.php并没有__call这个方法呀？难道必须我们自己写吗？那这叫什么狗屁漏洞，别急IndexController类确实没有但是默认会继承一个父类Controller类。</span></strong></p></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZGhP0Qh49w2jhroOcdibaia3NQMxk38GNWEdweYyB9ZThkBjnGf0JwFqQ/640?wx_fmt=png "")  
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="font-size: 14px;"><strong>可以看到确实存在这个魔术方法，$method-&gt;invokeArgs($module, array($action, &#39;&#39;)); array($action, &#39;&#39;)其中$action是我们可以控制的也就是a,function __call($method, $args) $method也就是$action。</strong></span></p><p style="margin: 0;padding: 0;min-height: 24px;text-indent: 2em;"><span style="font-size: 14px;"><strong>等等我在__call看到了什么$this-&gt;display();搜嘎我相信到这里就清楚了吧，第一个if输出一下就知道了，第2个method_exists判断当前类里面存在不存在_empty，也可以过了因为默认没有，parseTemplate跟进去看看呗。</strong></span></p></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZsILwJMTkwXa2UG17Ebia0iaAPxvnAAyuUI4U6m4ia2ia4ic1kkOvX0Uyxjw/640?wx_fmt=png "")  
```
if ('' == $template) {
      // 如果模板文件名为空 按照默认规则定位
      $template = CONTROLLER_NAME . $depr . ACTION_NAME;
  } elseif (false === strpos($template, $depr)) {
      $template = CONTROLLER_NAME . $depr . $template;
  }
  $file = THEME_PATH . $template . C('TMPL_TEMPLATE_SUFFIX');
  if (C('TMPL_LOAD_DEFAULTTHEME') && THEME_NAME != C('DEFAULT_THEME') && !is_file($file)) {
      // 找不到当前主题模板的时候定位默认主题中的模板
      $file = dirname(THEME_PATH) . '/' . C('DEFAULT_THEME') . '/' . $template . C('TMPL_TEMPLATE_SUFFIX');
  }
  return $file;
这个是漏洞产生的原因，也是执行到$this->display();造成文件包含的原因，因为$this->display();里面也执行了parseTemplate方法。
$template本来就是空的，ACTION_NAME常量是我们一路看过来的东西就是a,C('TMPL_TEMPLATE_SUFFIX')输出了一下是html的，然后返回了$file。
```  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">然后还有一个file_exists_case方法我就不解释了下面是图就是看文件存在不存在。</span></strong></p></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZKmBqtUibVu4egl72iciaorcW0ZvAXR9XcGYP9t8PWViaeiaUFAuj7qLxZOw/640?wx_fmt=png "")  
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">最后执行了$this-&gt;display();跟进去。</span></strong></p></td></tr></tbody></table>  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZaWcicll22bSiaVfDp34Iiap7a0ibNHVMAbL5BYUAvhf4dsA1xXZPFJAzkg/640?wx_fmt=png "")  
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">继续呗。</span></strong></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZJQJmPoEpB4z8qpIsEVZgwWLcobFavQcGP1MedumXYe60GDjXzm4BFQ/640?wx_fmt=png "")  
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">看看fetch，121行和我上面说的一样就不进去看了，$templateFile是我们可以控制的，到了154行给了一个数组里面$params，155行进去看看对数组做了什么。</span></strong></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZPsQD4cpRCKA3w7GZRibsRviab21FZgLicALMab40FmhSUyKV9iacUB3tUQ/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZkRz0EYBicOVQyMVpzVkp1KX5AjsBiaOE6Gl0sBTcgnkiadezcP2lc1INA/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZLO9UPEs3kvMia8GP3KiaOFMwoEaKBa9027VKajxQPE76aoSM02WbVicxg/640?wx_fmt=other&from=appmsg "")  
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">接着看看self::exec</span></strong></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1Zh6MZme7abF06cDvKu4HMNSheZRdQLAgBe9J2Qf7nTJ3Dy4KBpTZGPw/640?wx_fmt=png "")  
  
  
  
**不知道的直接输出一下。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1Z2bgoOVc7oTD1uzTymD8PicAqmmHiciaR1g94ibtYe1BxOtAHib4o3l0MU7Q/640?wx_fmt=png "")  
  
**当前类的run方法。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1Z2JavRKrr8S8TvBGm8QruVkiaqiaefIjXJfDScxK2kMBtKh4IOibO8Z8pg/640?wx_fmt=png "")  
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">Template类的fetch</span></strong></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1Z9ddRbWvBYhJmNfDNzDcpN868XUhZuyIqKFghic7dcugrYNqn0jloYLg/640?wx_fmt=png "")  
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">接着进入loadTemplate这块我就不具体说了可以看Thinkphp3变量覆盖导致rce的文章，简单来说就是把文件进行读取出来130把内容进行过滤（这块的过滤可以忽略），然后创建缓存文件，131行把内容写入到缓存文件里面，最后返回这个缓存文件的路径之后执行Storage::load。</span></strong></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1Za4AL4tgV9kePfibdRhpLwqPA1RQymTCJyLp8cf1aweuBgDIBPFV1zMg/640?wx_fmt=png "")  
  
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><span style="font-size: 14px;"><strong>Storage::load跟进去看看</strong></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZEtytoskicNc9coibuez8wgiaOyUVZa4prInzJyA6jm72iaP2czT05sIpuQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZlPnARiclZZG7ERrpyfwTgVyU9wpmTGtE6StjpX1BebVicwN0XmPt64SQ/640?wx_fmt=other&from=appmsg "")  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">到这也就是成功进行文件包含了但是存在条件就是，上面我们分析到C(&#39;TMPL_TEMPLATE_SUFFIX&#39;)</span></strong></p><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">是html所以只能包含html的文件。</span></strong></p></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZRzlJPPIouhdPyCLicWKmXI7ncKYenEFD3SFMS7C5iaqdc3WLerkzeJSw/640?wx_fmt=png "")  
  
  
  
  
  
# 三.漏洞利用    
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p><strong><span style="mso-bookmark:ufac7dbd8;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">首先在根目录下面创建一个文件名字随便但是必须是html扩展名，内容为php的代码,就phpinfo吧</span></span><span style="mso-bookmark:ufac7dbd8;"><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:Times New Roman;font-variant:normal;text-transform:none;"></span></span><span style="mso-bookmark:ufac7dbd8;"></span><span style="mso-bookmark:ufaaba640;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color="">poc: </span></span></strong><span style="mso-bookmark:ufaaba640;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color=""><br/></span></span></p><p><span style="mso-bookmark:ufaaba640;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 255);font-weight: normal;font-style: normal;text-decoration: none; ; " data-darkreader-inline-color="">http://127.0.0.1/index.php?m=Home&amp;c=index&amp;a=../../../../../2</span></span></p></td></tr></tbody></table>  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yahibu90Jz3TG5gtUApeNm1ZKh9AjmqvlUTjBOdicUxr0EWlCtedvuK4TMZjMgWVYibTzdDM0foohqUw/640?wx_fmt=png "")  
  
  
  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin: 0;padding: 0;min-height: 24px;"><strong><span style="font-size: 14px;">Thinkphp3已经不再更新维护了，但是有很多优秀项目依然在使用tp3，这里就简单举个例子，在我写这篇文章的时候showdoc-3.2.6目前最新版本一下都存在这个漏洞。</span></strong></p></td></tr></tbody></table>  
    
# 四：GETshell   
  
  
还在尝试中......  
      
  
  
微信公众号用不习惯格式可能会有部分错误，查看语雀原文公众号回复:Think3  
  
