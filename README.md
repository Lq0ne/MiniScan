# MiniScan

自动反编译小程序并使用Fortify审计JS源码

## 使用方法

运行Mini-Scan.py -scan，程序将自动监听新开启的小程序并进行反编译，完成后调用本机fortify进行自动化代码审计、报告生成。

反编译源码目录：./result/

代码审计结果和日志保存目录：./scan_results

使用前请先下载fortify在fortify_scan.py中配置fortify路径和OpenText报告生成工具路径

![image-20251104145354233](https://raw.githubusercontent.com/Lq0ne/MiniScan/refs/heads/main/assets/image-20251104145354233.png)


#开发日志
Output文件存放程序输出
Output\Audit存放代码审计结果
Output\Log存放程序日志
Output\Source存放反编译完成的源码

-scan 批量扫描模式
-monitor 监控扫描模式

-scan：
该模式会清理微信小程序缓存文件夹！！！
经过确认后，该模式将开始监听接下来打开的所有小程序，建议等小程序界面完全加载出来后再关闭，之后再开启下一个小程序即可，全部加载完后，输入Start即可开始批量自动化反编译和代码审计。

Config文件配置见config\config.yaml注释