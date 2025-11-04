# MiniScan

自动反编译小程序并使用Fortify审计JS源码

## 使用方法

运行Mini-Scan.py -scan，程序将自动监听新开启的小程序并进行反编译，完成后调用本机fortify进行自动化代码审计、报告生成。

反编译源码目录：./result/

代码审计结果和日志保存目录：./scan_results

使用前请先下载fortify在fortify_scan.py中配置fortify路径和OpenText报告生成工具路径

![image-20251104145354233](https://raw.githubusercontent.com/Lq0ne/MiniScan/refs/heads/main/assets/image-20251104145354233.png)