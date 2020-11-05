#!/bin/sh
#该函数测量访问某内存addr的时间
#高精度计数：https://www.felixcloutier.com/x86/rdtscp
#__rdtscp：产生64位时间戳结果
cat <<-'EOF'
	static inline int
	get_access_time(volatile char *addr)
	{
		unsigned long long time1, time2;
EOF
#Assuming you are compiling for x86, there is a __rdtscp builtin function
#rdtsc：https://docs.microsoft.com/en-us/cpp/intrinsics/rdtsc?view=msvc-160
if grep -q rdtscp /proc/cpuinfo; then   #判断cpu架构是否支持
	cat <<-'EOF'
		unsigned junk;
		time1 = __rdtscp(&junk); 
		(void)*addr;
		time2 = __rdtscp(&junk);
	EOF
else   #(void)*addr;表示访问了addr内存
	cat <<-'EOF'
		time1 = __rdtsc();
		(void)*addr;
		_mm_mfence();
		time2 = __rdtsc();
	EOF   #An _mm_mfence is a hardware thing that makes sure any processors cache on stores are written to memory.【写回】
fi  
cat <<-'EOF'
		return time2 - time1;
	}
EOF
