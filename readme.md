最近看了几个iot的漏洞，发现有很多命令注入类型的，模拟一个路由器耗费时间过久，于是写了一个简洁的命令注入的二进制文件供学习测试，源码见hub_daemon.c文件，然后主要还是一个sprintf导致的漏洞
    snprintf(command, sizeof(command), "ping -I %s -c %d %s 2>&1",
             iface->valuestring, ping_count, target->valuestring);
    printf("[System] Executing: %s\n", command);

    FILE *fp = popen(command, "r");
通过这里进行一个命令注入，最终利用脚本见exp.py，可以进行一个反弹shell的操作