// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/libkern/OSCacheControl.h

enum macro_cache_function {
/* Prepare memory for execution.  This should be called
 * after writing machine instructions to memory, before
 * executing them.  It syncs the dcache and icache.
 * On IA32 processors this function is a NOP, because
 * no synchronization is required.
 */
/*line: 43*/    kCacheFunctionPrepareForExecution = 0x1,  // 1
/* Flush data cache(s).  This ensures that cached data 
 * makes it all the way out to DRAM, and then removes
 * copies of the data from all processor caches.
 * It can be useful when dealing with cache incoherent
 * devices or DMA.
 */
/*line: 51*/    kCacheFunctionFlushDcache = 0x2,  // 2
};

