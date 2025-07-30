> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MTUwMjQ5Nw==&mid=2247489257&idx=1&sn=736e8d509921cfc4ceb2408cc387ec7f

#  在受限 SQL 注入场景中枚举 MySQL 8.x 和 9.x 中表名的有趣技术  
原创 红云谈安全  红云谈安全   2025-06-26 14:16  
  
**免责声明**  
  
由于传播、利用本公众号红云谈安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号红云谈安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！请在授权的站点测试，遵守网络安全法！  
**仅供**  
**学习使用，****如若非法他用，与平台和本文作者无关，需自行负责！**  
  
我在参与一个私人漏洞赏金计划时，发现 LIMIT 子句中存在一个 SQL 盲注入，这个漏洞利用起来非常棘手。我们的输入被传递给一个 SQL 查询，如下所示：  

```
SELECT whatever_column FROM whatever_table LIMIT {{our_input}}
```

  
我们无法使用多个语句，而且在 MySQL 的 LIMIT 子句中也无法进行子查询。起初，除了注意到响应中的偏移量变化之外，我什么也做不了  

```
1 OFFSET 2#
```

  
，但这不足以证明其影响。  
  
我在网上搜索了所有可以利用 limit 子句中的 MySQL 注入的方法，但我所发现的只是一种使用 MySQL 5.x 中的过程的技术，而该技术在较新版本的 MySQL 中不再起作用，因为我们不再可以在 LIMIT 子句之后使用过程。  
  
那么现在该怎么办？我查看了 MySQL 8.x 文档，发现了一些非常有趣的事情：  

```
.
.
.
[LIMIT {[offset,] row_count | row_count OFFSET offset}]
[into_option]
[FOR {UPDATE | SHARE}
    [OF tbl_name [, tbl_name] ...]
    [NOWAIT | SKIP LOCKED]
    | LOCK IN SHARE MODE]
```

  
明白我们要做什么了吗？我们可以使用这样的payload：  

```
vuln_param = 1 + FOR + SHARE + OF + table_name#
```

  
如果表存在，我们将收到 200 响应代码。如果不存在，我们将收到 500 错误。  
  
我使用 python 自动破解数据库中的表，并能够提取 4 个有效的表名。  
## 笔记 ：  
  
此技术仅提取查询中使用的表，但如果选项不足，它会非常方便。如果您受到严格的 WAF 限制，则可以使用此方法提取一些有效的表名。  
  
  
  
  
