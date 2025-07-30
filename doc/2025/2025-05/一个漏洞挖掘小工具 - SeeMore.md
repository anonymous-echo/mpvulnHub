#  一个漏洞挖掘小工具 - SeeMore   
Bbdolt  安全洞察知识图谱   2025-05-19 00:29  
  
**免责声明**  
 由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号安全洞察知识图谱及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
## 1工具介绍  
  
1、在某系统发现在导入文件时，文件内容没有进行过滤导致存储型xss注入，可以发送任何人或提交模板（管理员会审查）危害挺大的，然后提交漏洞后他进行了修复。  
  
2、但是  
程序员只是将导入功能的元素添加"display: none;"隐藏起来了， 但是这个功能还是存在，所以可以通过将"display: none;"删除达到显示导入功能（二次绕过）。  
  
3、这里再提供一思路，在第2次修复后，程序员可能只是将页面对应的代码段删除，但是后端的api仍然存在，可以利用之前的数据包（可能需要修改Cookie） 进行重放攻击。  
  
但是如果每次都要去手动修改不可见元素为可见就太麻烦了，还可能错过一些可利用的功能点，所以就做了这个插件可以显示隐藏的可点击（重点）元素，不会将一些无用的文本弹窗等显示出来造成页面的不美观，下面讲讲这个插件的应用场景以及安装方法。  
  
如果大家在使用过程中遇到了bug或一些没有成功显示的元素，可以提交到issues中，作者会尽快完善匹配规则，感谢大家支持。  
  
  
使用  
  
1、这里以Webgoat靶场为例  
  
![PixPin_2025-03-01_19-58-08](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8KQWL0jkMjwBiaEYJDibJ2Qib1pzWnVMXKOFicxd3zicsKzkaLDn449WrvQhvPLPiawEF9gbqrxtWicwAtw/640?wx_fmt=jpeg "")  
  
2、点击 Show Hidden 即可，显示出隐藏的按钮。点击 recover 即可恢复之前的页面。  
  
![PixPin_2025-03-01_20-00-28](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8KQWL0jkMjwBiaEYJDibJ2QibJrXPFtXnoIN7BWwAA7OUTd6DS63KkKpqu1gQc5Cm5pAKB6LmHc59bA/640?wx_fmt=jpeg "")  
  
3、安装教程，Google 打开 chrome://extensions/ 链接，开启开发者模式，点击"加载以解压的扩展程序"，选择下载解压后的文件夹导入即可。  
  
  
![PixPin_2025-03-01_20-02-55](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8KQWL0jkMjwBiaEYJDibJ2QibA4IdckNFdtjedHeLozvtnmXmWaic7SNvKmy1UuLcEn7q3zmUsnze4FA/640?wx_fmt=jpeg "")  
  
![PixPin_2025-03-01_20-03-24](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8KQWL0jkMjwBiaEYJDibJ2QibyrLG1tjHsEaibureyTBpPbBgMj2ibbK2KiaOLhVR7cagv8O1VNPmvuRsQ/640?wx_fmt=jpeg "")  
#### V1.0.1更新  
  
1、添加显示通过 <!-- 注释隐藏起来的可点击内容，这个页面存在隐藏的功能框  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8KQWL0jkMjwBiaEYJDibJ2QibIegqbsgaia9l5eL6vf5DjDjtj448RufUGvU5JWN34iaEJV7FMbwbxpiaQ/640?wx_fmt=jpeg "")  
  
2、点击 Show Hidden 显示功能  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8KQWL0jkMjwBiaEYJDibJ2QibvdIBejHX4JInbCaCf6icx3Yd5EVhUCA0pUFOiaxkkJj0VpsVpLV9JWlw/640?wx_fmt=jpeg "")  
#### v1.0.2更新  
#### 修复部分bug（注释功能）  
#### 案例补充  
  
发现上传功能，可以上传任意后缀但是对于大多数文件不解析，但可以解析html文件  
  
![image](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8KQWL0jkMjwBiaEYJDibJ2QibcmLsibB6aYvDibmr3Z27RLsjdKSqQXCRWhgnAX9EUbm6SccLOkib7Vr9A/640?wx_fmt=jpeg "")  
  
项目地址  
  
**https://github.com/Bbdolt/SeeMore**  
## 2免费社区  
  
安全洞察知识图谱星球是一个聚焦于信息安全对抗技术和企业安全建设的话题社区，也是一个  
**[免费]**  
的星球，欢迎大伙加入积极分享红蓝对抗、渗透测试、安全建设等热点主题  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PDVoxXx6Rh8aia4mibs0I8I42MrYYOSE2DVEpVpPHvxufMGR0yufpgouwIXEl7H5eLm0MgolGFQMDFIrKLTxaYIQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
