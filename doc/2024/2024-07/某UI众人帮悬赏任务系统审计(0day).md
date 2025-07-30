#  某UI众人帮悬赏任务系统审计(0day)   
Mstir  星悦安全   2024-07-07 19:06  
  
0x01 前言  
  
**Fofa:**  
```
请见文末
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpeDicBKylNG5iaMfaEqDN8FKsDMUHxc4mCnLxPcaiav2MnP8DnY5zygA3A/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpPU7MibXg0zp76GkKZArADDudyhEibwIfrEapIFAhhQgJJutDHDegQTkQ/640?wx_fmt=png&from=appmsg "")  
  
**框架:ThinkPHP 5.0.24 Debug:True**  
## 0x01 前台任意文件上传漏洞  
  
**全局搜索Thinkphp的原生上传函数file()，能找到非常多的上传点，大部分都不需要鉴权，但是不返回文件上传地址**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpJK2QAC7FO253hRUkicre734N0QC1OnQUxhFaTYYniaL4guaBkMyaOJHA/640?wx_fmt=png&from=appmsg "")  
  
**在 /home/controller/xxxx.php 控制器的xxxx方法中，上传之后通过Json_encode返回了Json编码后的文件上传地址.**  
```

//上传图片
public function xxxx(){
  $file = request()->file('xxxx');
  $qninfo = $this->qiniuupload($file);
  if(!$qninfo){
    message('图片错误','','error');
  }
  $data['img'] = $qninfo;
  echo json_encode($data);
}
```  
  
**这里是经过qiniuupload()方法上传的，我们可以跟踪一下，看起来像是用七牛云上传了，但实际是本地上传直接Return返回了，下面还有个die().**  
```
public function qiniuupload($file)
{
    $filePath = $file->getRealPath();
    $ext = pathinfo($file->getInfo('name'), PATHINFO_EXTENSION);  //后缀

    $info = $file->move(ROOT_PATH . 'public' . DS . 'uploads');
    if($info){
      return  '/uploads/'.$info->getSaveName();
    }else{
      return false;
    }
    die;


    //获取当前控制器名称
    //$controllerName=$this->getContro();
    // 上传到七牛后保存的文件名
    $key =substr(md5($file->getRealPath()) , 0, 5). date('YmdHis') . rand(0, 9999) . '.' . $ext;
    require_once APP_PATH . '/../vendor/qiniu/autoload.php';
    // 需要填写你的 Access Key 和 Secret Key
    $accessKey = config('ACCESSKEY');
    $secretKey = config('SECRETKEY');
    // 构建鉴权对象
    $auth = new Auth($accessKey, $secretKey);
    // 要上传的空间
    $bucket = config('BUCKET');
    $domain = config('DOMAIN');
    $token = $auth->uploadToken($bucket);
    // 初始化 UploadManager 对象并进行文件的上传
    $uploadMgr = new UploadManager();
    // 调用 UploadManager 的 putFile 方法进行文件的上传
    list($ret, $err) = $uploadMgr->putFile($token, $key, $filePath);
    if ($err !== null) {
      return false;
    } else {
      return 'http://'.$domain.'/' . $ret['key'];
    }
  }
```  
所以咱们构造Payload:```
请见文末！

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp1hFLHfcL1RkOeWsAZfKeVZ8S5XcFg1JeicARCjiczYSw1qz78c3b8QhQ/640?wx_fmt=png&from=appmsg "")  
  
0x02 后台权限绕过漏洞  
  
**默认后台登录 /admin/auth/login.html**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpZrNjicPGpbM0IAd9DIEK9M4F0osVXZzUh5EgSXr2qs5T3CwFNuajn0g/640?wx_fmt=png&from=appmsg "")  
  
**首先咱们看看登录接口 位于 /admin/controller/Auth.php 控制器的 Login 方法**  
  
**先是通过验证密码是否正确，然后给Cookie赋值 Cookie::set('administrator',base64_encode($administrator)); 之后直接exit跳转到 /admin/index/index 中**  
```
public function login(){
  $ip=getIp();
  // if($ip == '115.62.210.41' || $ip == '229.153.90.235'){
  // }else{
  //     die;
  // }
  if(request()->isAjax()){
    $params = request()->post();
    $result = $this->validate($params,'Administrator.login');
    //            if($result !== true){
    //                message($result,'','error');
    //            }
    $administrator = Administrator::getInfoByUsername($params['username']);
    if(empty($administrator)){
      message('管理员信息不存在','','error');
    }
    if(!md5_password_check($params['password'],$administrator['password'],$administrator['salt'])){
      message('密码输入错误，可前往71jc.cn获取账号密码','','error');
    }
    Cookie::set('administrator',base64_encode($administrator));
    cache('DB_TREE_MENU_' . $administrator['id'], NULL);
    message('登录成功', U('index/index'), 'success');
  }
  Cookie::delete('administrator');
  return $this->fetch(__FUNCTION__);
}
```  
  
**基本上所有admin集合中的控制器都继承于Base控制器 所以实际鉴权函数在 /admin/controller/Base.php 控制器的 _checkLogin 方法中.******  
```
private function _checkLogin(){
  if(Cookie::has('administrator')){
    $this->administrator = (array)json_decode(base64_decode(Cookie::get('administrator')));
  }
  //未登录，当前控制器不属于免登录
  if(!in_array(request()->controller(),['Auth']) && !check_array($this->administrator)){
    if(request()->isAjax()){
      message('请先登录', U('auth/login'), 'error');
    }
    $this->redirect(U('auth/login'));
  }
}
```  
  
**仅仅是验证经过Base64解码后的Cookie值administrator 这里就非常可能存在权限绕过漏洞了.**  
  
**咱们先模拟正常登录的流程，直接登录，然后就能看到被赋值的Cookie**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp3Xwe5ngbicTMjQauLRSCO2XI8ib2czm8t5kpE3zm82kCQdibLTnpRkUtA/640?wx_fmt=other&from=appmsg "")  
  
**咱们Base64解码一下 推荐用**  
  
**https://www.toolhelper.cn/EncodeDecode/Base64 这个解码**  
  
****  
**可以发现是json编码的信息，经过验证我们发现仅需要 id username avatar 这三个字段即可绕过登录(其实少了avatar也行，但是大部分接口就不能用了，会报错)**  
  
**咱们编码一下得到这样一串:**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpqaEVv9mRubGN458WOBzJ5yfiaIiaDECrw4DIdBo2wHbFPkWxrfYnKUOQ/640?wx_fmt=png&from=appmsg "")  
  
**咱们将所有Cookie清除，退出登录，然后直接利用Hackbar伪造 Cookie 访问功能点，可以看到成功绕过进入后台了.**  
  
**Payload:**  
```
请见文末
```  
  
‍![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp5YyDUjHibDS4ByZiaohHdURlOotC2ichflDtQUWRV1Y31WLWgZK2c4ic1A/640?wx_fmt=png&from=appmsg "")  
  
  
**完整文章及源码请见下方纷传圈子最新文章**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
**圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
高  
质量漏洞利用研究，代码审计圈子，每天至少更新一个0Day/Nday/1day及对应漏洞的批量利用工具，团队内部POC，源码分享，星球不定时更新内外网攻防渗透技巧以及最新学习，SRC研究报告等。  
  
**【圈子服务】**  
  
1，一年至少999+漏洞Poc及对应漏洞批量利用工具  
  
2，各种漏洞利用工具及后续更新，渗透工具、文档资源分享  
  
3，内部漏洞库情报分享（目前已有1110+poc，会每日更新，包括部分未公开0/1day）  
  
4，加入内部微信群，遇到任何技术问题都可以进行快速提问、讨论交流；  
  
  
圈子目前价格为**40元**  
**(交个朋友啦！)**  
，现在星球有近200+位师傅相信并选择加入我们  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp3ia3SDgr5JR95vpHUfjgnuhAvzsNriaca9Fc4FdeOibib4icWFXN4YrXRXQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
**圈子内部漏洞库(日更)**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=wxpic "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp1mjkFMGrZ9mEvvWqrIbSUiaIrfU70EqE0GszjkYLbs2OUlFhwU86IPg/640?wx_fmt=png&from=appmsg "")  
  
**实时更新日志 : http://8.219.168.142/**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp5BoQzhn5vyWZ4MmUWYuHgqjbUx1KtsoFwMBDwRU5F1HSXk67Exmwzg/640?wx_fmt=png&from=appmsg "")  
  
**每篇文章均有详细且完整指纹及利用POC**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpiaCr1T3L5qvOVBhYVo3Nt2SfMTmkNBtD1OuvmwlFaqjbK8hqFricCOsA/640?wx_fmt=png&from=appmsg "")  
  
**一起愉快地刷分**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp1nDJvFuhT6INWEyGaCkEEclfEo8Ld6OBOzzJ3BkTVbrfqd41XhAhicA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpt1uZwVAmW8XEscyvU51uc9sdiaHViaJKMEZyiaM4bAaQfGIPNd26u2A5w/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpPGVahCuyNFFdRtlOyjb6Z1dj8LMnibicPickAJZQLpTzoBoUqy9Xun3tg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dbasJicXJDEOR85icHkfIda3gg2HpaWjW2MZN9KZdGzX99Ofl7SRETFA4TicFabIO2UGibSONn6bhXQw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**标签:代码审计，0day，渗透测试，系统，悬赏，APP，Fofa，源码**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HVNK6rZ71oofHnCicjcYq2y5pSeBUgibJg8K4djZgn6iaWb6NGmqxIhX2oPlRmGe6Yk0xBODwnibFF8XCjxhEV3K7w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
    **文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
