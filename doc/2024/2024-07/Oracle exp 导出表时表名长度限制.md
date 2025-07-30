#  Oracle exp 导出表时表名长度限制   
原创 hyang0  生有可恋   2024-07-17 20:03  
  
在使用 exp 批量导出表时，遇到一个报错：  
```
$ export NLS_LANG=AMERICAN_AMERICA.UTF8
$ exp --/-- file=exp.dmp tables=\(门诊处方表,医院项目医保目录映射表,病案首页表,挂号表\)
. . exporting table ...
. . exporting table  医院项目医保目录映射
EXP-00056: ORACLE error 942 encountered
ORA-00942: table or view does not exist
```  
  
查了下数据库，发现表是存在的，但与日志中的表名相比，日志中少了一个字。以为是命令敲错了，对照了下命令发现的确日志中的表名少了一个字。  
```
医院项目医保目录映射表
医院项目医保目录映射
```  
  
**导出工具 exp 对于中文表名，表名长度最长只支持10个字符。**  
  
因为数据审计方要求表名是中文的，所以在建表时使用了中文表名。数据库使用的是 11.2.0.4，不知道是不是该版本的bug，没有去MOS上查。在重新调整表名长度后，单独对问题表进行导出，导出命令可以正常导出：  
```
SQL> rename table 医院项目医保目录映射表 to 医院项目医保目录映射
SQL> 
$ exp --/-- file=exp.dmp tables=\(医院项目医保目录映射\)

Export: Release 11.2.0.4.0 - Production on Wed Jul 17 18:45:40 2024

Copyright (c) 1982, 2011, Oracle and/or its affiliates.  All rights reserved.


Connected to: Oracle Database 11g Enterprise Edition Release 11.2.0.4.0 - 64bit Production
With the Partitioning, Real Application Clusters, Automatic Storage Management, OLAP,
Data Mining and Real Application Tes
Export done in UTF8 character set and AL16UTF16 NCHAR character set
server uses ZHS16GBK character set (possible charset conversion)

About to export specified tables via Conventional Path ...
. . exporting table  医院项目医保目录映射  134485 rows exported
Export terminated successfully without warnings.
```  
  
全文完  
。  
  
