/*
 game_over, part 2 - the game-over-en-ing
 
 offsets time & provides global env injection
 */

#include <mach/mach_time.h>
#include <malloc/malloc.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <spawn.h>
#include <time.h>

#include <objc/runtime.h>
#include <objc/message.h>

#define SYSLOG 1
#define SYSLOG_OTHER 0
#define SYSLOG_TIME_LOG 0

#define CLOCK_GETTIME_DO 0

#ifdef SYSLOG
#if SYSLOG
#define _syslog(log_level, str, args...) do { syslog(log_level, str, ##args); printf(str "\n", ##args); } while(0)
#else
#define _syslog(log_level, str, args...) do {} while(0)
#endif
#endif

#ifdef SYSLOG_OTHER
#if SYSLOG_OTHER
#define _syslog_other(log_level, str, args...) do { syslog(log_level, str, ##args); printf(str "\n", ##args); } while(0)
#else
#define _syslog_other(log_level, str, args...) do {} while(0)
#endif
#endif

#ifdef SYSLOG_TIME_LOG
#if SYSLOG_TIME_LOG
#define _syslog_time_log(log_level, str, args...) do { syslog(log_level, str, ##args); printf(str "\n", ##args); } while(0)
#else
#define _syslog_time_log(log_level, str, args...) do {} while(0)
#endif
#endif

#define __32_BIT__ (UINTPTR_MAX == 0xffffffff)

#if __32_BIT___
#define POINTER_SIZE 4
#else
#define POINTER_SIZE 8
#endif

#if __arm__ || __arm64__
#define UNTETHER_STRING "/untether/game_over_armv7.dylib1"
#else
#define UNTETHER_STRING "./bin/game_over.dylib"
#endif

//typedef enum { false, true } bool;

bool interpose_hax();

extern char** environ;

bool do_it = true;
bool syslog_it = true;

void ensure_env() {
	if (syslog_it)
		_syslog_other(LOG_SYSLOG, "setting envs, just in case"); // THIS CAUSES A SEGFAULT IN gettimeofday! IT RECURSIVELY FUCKS UP EVERYTHING!!!
	char* DYLD_INSERT_LIBRARIES = getenv("DYLD_INSERT_LIBRARIES");
	if (!DYLD_INSERT_LIBRARIES)
		setenv("DYLD_INSERT_LIBRARIES", UNTETHER_STRING, 0);
	else {
		char* set_me;
		if (strstr(DYLD_INSERT_LIBRARIES, UNTETHER_STRING) == NULL)
			asprintf(&set_me, "%s:" UNTETHER_STRING, DYLD_INSERT_LIBRARIES);
		else
			asprintf(&set_me, "%s", DYLD_INSERT_LIBRARIES);
		
		if (set_me)
			setenv("DYLD_INSERT_LIBRARIES", set_me, 1);
		
		free(set_me);
	}
}

uint32_t get_offset() {
	char* __OFFSET = getenv("__OFFSET");
	int offset = 0;
	if (__OFFSET) {
		offset = atoi(__OFFSET);
//		free(__OFFSET);
	}
	if (!offset) {
		offset = 42069;
	}
	return offset;
}

void __before_hook() {
	ensure_env();
	printf("[*] before_hook\n");
}

void __before_exec(int line, const char* s) {
	/*
	 before_exec hook
	 */
}

#if CLOCK_GETTIME_DO
int _clock_gettime(clockid_t clk_id, struct timespec *tp) {
	__before_hook();					// fix up stuff

	clockid_t clk_id_ = clk_id;			// recreate variables
	struct timespec tp_;
	int ret;							// return val

	long old_tv_sec;					// for logging
	
	ret = clock_gettime(clk_id_, &tp_);	// call original
	
	old_tv_sec = tp_.tv_sec;			// set old
	
	if (do_it) {
		tp_.tv_sec += get_offset();		// get offset, and add it
	}

	_syslog_time_log(LOG_SYSLOG, "[c] %ld, %ld", old_tv_sec, tp_.tv_sec);
	
	memcpy(tp, &tp_, sizeof(struct timespec));
	return ret;
}
#endif

time_t _time(time_t* t) {
	__before_hook();					// fix up stuff

	time_t t_;							// recreate variables
	time_t ret;							// return val
	ret = time(&t_);					// get time

	time_t old_t_ = t_;					// for logging
	
	if (do_it) {
		t_ +=get_offset();				// get offset, and add it
	}
	
	_syslog_time_log(LOG_SYSLOG, "[t] %ld, %ld\n", old_t_, t_);
	
	if (t)
		*t = t_;						// gawd damn segfaults!

	return t_;
}

uint64_t _mach_absolute_time(void) {
	/*
	 mach_absolute_time hook is disabled for now, creates weird (read: fun)
	 UI bugs
	 */

	__before_hook();					// fix up stuff
	uint64_t at = mach_absolute_time();	// get return
	
#if 0
	long old_tv_sec;
	
	uint64_t add = get_offset();
	add *= 1000000000; // seconds -> nanoseconds
	
	uint64_t ret = at;
	
	uint64_t old_ret = ret;
	
	if (do_it) {
		ret += add;
	};

	_syslog_time_log(LOG_SYSLOG, "[m] %llu, %llu", old_ret, ret);
	
	return ret;
#else
	return at;
#endif
}

int _gettimeofday(struct timeval *restrict tv,
				  struct timezone *restrict tz) {

	syslog_it = false;					// syslog uses gettimeofday, using 
										// syslog in this function causes 
										// a recursive loop

	__before_hook();
	syslog_it = true;
	struct timeval tv_;
	struct timezone tz_;
	gettimeofday(&tv_, &tz_);
	
	long old_tv_sec = tv_.tv_sec;
	
	tv_.tv_sec += get_offset();
	tv_.tv_usec += 0;
	
//	_syslog(LOG_SYSLOG, "[g] %ld, %ld", old_tv_sec, tv_.tv_sec);

	/*
	 SYSLOG CAN NOT BE CALLED IN THIS FUNCTION
	 IT ENTERS AN INFINITE LOOP
	 */
	
	if(tv)memcpy(tv, &tv_, sizeof(struct timeval));
	if(tz)memcpy(tz, &tz_, sizeof(struct timezone));
	
	return 0;
}

int _setenv(const char *var_name, const char *new_value, int change_flag) {
	__before_hook();									// fix up stuff

	int ret = setenv(var_name, new_value, change_flag);	// call original function

	ensure_env();										// fix up again
	return ret;
}

int _putenv(char *var_name) {
	__before_hook();			// fix up stuff

	int ret = putenv(var_name);	// call original function

	ensure_env();				// fix up again
	return ret;
}

#if !__arm__ && !__arm64__
int _system(const char *command) {
	/* 
	 this is dumb, system isn't even on iOS, and if it is, 
	 it's gotten from dlsym, so this won't work!
	 */
	__before_hook();
	__before_exec(__LINE__, command);
	return system(command);
}
#endif

int _execv(const char *filename, char *const argv[]) {
	__before_hook();					// fix up stuff
	__before_exec(__LINE__, filename);	// more hooks
	return execv(filename, argv);		// call original
}

int _execl(const char *filename, const char *arg0, ...) {
	__before_hook();					// fix up stuff
	__before_exec(__LINE__, filename);	// more hooks

	/*
	 let's do a code rundown.

	 first, it takes the arg0 pointer, and uses it as an array/vector of
	 pointers (which it essentially is, just that it's the first (0th) item)

	 it then counts how many pointers it takes to get to the NULL pointer,
	 the end of the list for execl and co

	 then, it allocates a new array, and puts those pointers in the array.

	 then it calls execv with that array.
	 */
	
	char** _argv = NULL;
	int count = 0;
	int ret;
	
	while (*(arg0 + (count * POINTER_SIZE)))
		count++;
	
	_argv = (char**)malloc(count * POINTER_SIZE);

	for (int i = 0; i < count; i++) {
		_argv[i] = (char*)(arg0 + POINTER_SIZE);
	}

	ret = execv(filename, _argv);
	free(_argv);
	
	return ret;
}

int _execve(const char *filename, char *const argv[], char *const env[]) {
	__before_hook();
	__before_exec(__LINE__, filename);
	return execve(filename, argv, environ);
}

int _execle(const char *filename, const char *arg0, ...) {
	__before_hook();
	__before_exec(__LINE__, filename);
	
	char** _argv = NULL;
	int count = 0;
	int ret;
	
	while (*(arg0 + (count * POINTER_SIZE)))
		count++;
	
	_argv = (char**)malloc(count * POINTER_SIZE);

	for (int i = 0; i < count; i++) {
		_argv[i] = (char*)(arg0 + POINTER_SIZE);
	}

	ret = execve(filename, _argv, (char**)(arg0 + (((count + 2) * POINTER_SIZE))));
	free(_argv);
	
	return ret;
}

int _execvp(const char *filename, char *const argv[]) {
	__before_hook();
	__before_exec(__LINE__, filename);
	return execvp(filename, argv);
}

int _execlp(const char *filename, const char *arg0, ...) {
	__before_hook();
	__before_exec(__LINE__, filename);
	
	char** _argv = NULL;
	int count = 0;
	int ret;
	
	while (*(arg0 + (count * POINTER_SIZE)))
		count++;
	
	_argv = (char**)malloc(count * POINTER_SIZE);

	for (int i = 0; i < count; i++) {
		_argv[i] = (char*)(arg0 + POINTER_SIZE);
	}

	ret = execvp(filename, _argv);
	
	return ret;
}

int _posix_spawn(pid_t *restrict pid, const char *restrict path,
				const posix_spawn_file_actions_t *restrict file_actions,
				const posix_spawnattr_t *restrict attrp,
				char *const argv[restrict],
				 char *const envp[restrict]) {
	__before_hook();
	__before_exec(__LINE__, path);
	return posix_spawn(pid, path, file_actions, attrp, argv, environ);
}
int _posix_spawnp(pid_t *restrict pid, const char *restrict file,
				const posix_spawn_file_actions_t *restrict file_actions,
				const posix_spawnattr_t *restrict attrp,
				char *const argv[restrict],
				  char *const envp[restrict]) {
	__before_hook();
	__before_exec(__LINE__, file);
	return posix_spawnp(pid, file, file_actions, attrp, argv, environ);
}

/* substitute */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <string.h>

#ifdef __LP64__
#define nlist_native nlist_64
#define LC_SEGMENT_NATIVE LC_SEGMENT_64
#define segment_command_native segment_command_64
#define mach_header_native mach_header_64
#define section_native section_64
#define PAGEZERO_SIZE 0x100000000;
#else
#define nlist_native nlist
#define LC_SEGMENT_NATIVE LC_SEGMENT
#define segment_command_native segment_command
#define mach_header_native mach_header
#define section_native section
#define PAGEZERO_SIZE 0x1000
#endif

__attribute__((noinline))
static void *find_lazy(uint32_t ncmds, const struct load_command *cmds, uintptr_t slide, const char *desired) {
    uint32_t symoff = 0, stroff = 0, isymoff = 0, lazy_index = 0, lazy_size = 0;
    void **lazy = 0;
    uint32_t cmdsleft;
    const struct load_command *lc;

    uintptr_t thisimage = (uintptr_t) &find_lazy - slide;

    for(lc = cmds, cmdsleft = ncmds; cmdsleft--;) {
        if(lc->cmd == LC_SYMTAB) {
            const struct symtab_command *sc = (void *) lc;
            stroff = sc->stroff;
            symoff = sc->symoff;
        } else if(lc->cmd == LC_DYSYMTAB) {
            const struct dysymtab_command *dc = (void *) lc;
            isymoff = dc->indirectsymoff;
        } else if(lc->cmd == LC_SEGMENT_NATIVE) {
            const struct segment_command_native *sc = (void *) lc;
            const struct section_native *sect = (void *) (sc + 1);
            uint32_t i;
            if(sc->vmaddr <= thisimage && thisimage < (sc->vmaddr + sc->vmsize)) return 0;
            for(i = 0; i < sc->nsects; i++) {
                if((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
                    lazy_index = sect->reserved1; 
                    lazy_size = sect->size / sizeof(*lazy);
                    lazy = (void *) sect->addr + slide;
                }
                sect++;    
            }
        }
        lc = (void *) ((char *) lc + lc->cmdsize);
    }

    if(!stroff || !symoff || !isymoff || !lazy_index) return 0;

#define CATCH(off, addr) if(sc->fileoff <= (off) && (sc->fileoff + sc->filesize) >= (off)) (addr) = (void *) (sc->vmaddr + slide + (off) - sc->fileoff);
    struct nlist_native *syms = 0;
    const char *strs = 0;
    uint32_t *isyms = 0;

    for(lc = cmds, cmdsleft = ncmds; cmdsleft--;) {
        if(lc->cmd == LC_SEGMENT_NATIVE) {
            struct segment_command_native *sc = (void *) lc;
            CATCH(symoff, syms);
            CATCH(stroff, strs);
            CATCH(isymoff, isyms);
        }
        lc = (void *) ((char *) lc + lc->cmdsize);
    }

    if(!syms || !strs || !isyms) return 0;

    uint32_t i;
    for(i = lazy_index; i < lazy_index + lazy_size; i++) {
        const struct nlist_native *sym = syms + isyms[i];
        if(!strcmp(strs + sym->n_un.n_strx, desired)) {
            return lazy;
        }
        lazy++;
    }

    return 0;
}

bool interpose(const char *name, void *impl) {
    const struct mach_header_native *mach_hdr;
    bool result = false;
    uint32_t i;
    for(i = 0; (mach_hdr = (void *) _dyld_get_image_header(i)); i++) {
        void **lazy = find_lazy(mach_hdr->ncmds, (void *) (mach_hdr + 1), _dyld_get_image_vmaddr_slide(i), name);
        if(lazy) {
//        	printf("%s\n", _dyld_get_image_name(i));
            result = true;
//        	mprotect((void*)(((uintptr_t)lazy) & (~0x1000)), 0x1000, PROT_READ | PROT_WRITE);
            *lazy = impl;
        }
    }
    return result;
}

bool interpose_hdr(const char *name, void *impl, const struct mach_header *mach_hdr, uintptr_t slide) {
    bool result = false;
    void **lazy = find_lazy(mach_hdr->ncmds, (void *) (mach_hdr + 1), slide, name);
    if(lazy) {
        result = true;
//        printf("hdr %s %s\n", _dyld_get_image_name(i), name);
//        mprotect((void*)(((uintptr_t)lazy) & (~0x1000)), 0x1000, PROT_READ | PROT_WRITE);
        *lazy = impl;
    }
    return result;
}

bool interpose_hax() {
	_syslog(LOG_SYSLOG, "hax teh envs");
	interpose("_setenv",				&_setenv);
	interpose("_putenv",				&_putenv);

	_syslog(LOG_SYSLOG, "haxing exec shit");
	interpose("_execl",					&_execl);
	interpose("_execlp",				&_execlp);
	interpose("_execle",				&_execle);
	interpose("_execv",					&_execv);
	interpose("_execve",				&_execve);
	interpose("_execvp",				&_execvp);
	interpose("_posix_spawn",			&_posix_spawn);
	interpose("_posix_spawnp",			&_posix_spawnp);

	_syslog(LOG_SYSLOG, "haxing mach_absolute_time");
	interpose("_mach_absolute_time",	&_mach_absolute_time);

	_syslog(LOG_SYSLOG, "haxing time shit");
#if CLOCK_GETTIME_DO
	interpose("_clock_gettime",			&_clock_gettime);
#endif
	interpose("_gettimeofday",			&_gettimeofday);
	interpose("_time",					&_time);

	return true;
}

bool interpose_hax_hdr(const struct mach_header* mh, uintptr_t slide) {
//	printf("interpose_hax_hdr\n");
//	_syslog(LOG_SYSLOG, "hax teh envs");
	interpose_hdr("_setenv",				&_setenv, mh, slide);
	interpose_hdr("_putenv",				&_putenv, mh, slide);

//	_syslog(LOG_SYSLOG, "haxing exec shit");
	interpose_hdr("_execl",					&_execl, mh, slide);
	interpose_hdr("_execlp",				&_execlp, mh, slide);
	interpose_hdr("_execle",				&_execle, mh, slide);
	interpose_hdr("_execv",					&_execv, mh, slide);
	interpose_hdr("_execve",				&_execve, mh, slide);
	interpose_hdr("_execvp",				&_execvp, mh, slide);
	interpose_hdr("_posix_spawn",			&_posix_spawn, mh, slide);
	interpose_hdr("_posix_spawnp",			&_posix_spawnp, mh, slide);

//	_syslog(LOG_SYSLOG, "haxing mach_absolute_time");
	interpose_hdr("_mach_absolute_time",	&_mach_absolute_time, mh, slide);

//	_syslog(LOG_SYSLOG, "haxing time shit");
#if CLOCK_GETTIME_DO
	interpose_hdr("_clock_gettime",			&_clock_gettime, mh, slide);
#endif
	interpose_hdr("_gettimeofday",			&_gettimeofday, mh, slide);
	interpose_hdr("_time",					&_time, mh, slide);

	return true;
}

void _dyld_wrapper(const struct mach_header* mh, intptr_t vmaddr_slide) {
//	_syslog(LOG_SYSLOG, "_dyld_wrapper: %p 0x%08lx", mh, vmaddr_slide);
	interpose_hax_hdr(mh, vmaddr_slide);
}

void* _dlopen(const char *filename, int flags) {
	_syslog(LOG_SYSLOG, "hooking dlopen");
	interpose_hax();
	return dlopen(filename, flags);
}

/* my code */
__attribute__((constructor)) static 
void game_over(int argc, const char **argv) {
	_syslog(LOG_SYSLOG, "0wn'd %d", getpid());
	_syslog(LOG_SYSLOG, "offset=%d", get_offset());
	_syslog(LOG_SYSLOG, "interposition...");

	interpose_hax();
	interpose("__dlopen", &_dlopen);
	interpose("_dlopen", &_dlopen);
	interpose("dlopen", &_dlopen);
#if __arm__ || __arm64__
	_dyld_register_func_for_add_image(&_dyld_wrapper);
#endif
	
	ensure_env();
	
	_syslog(LOG_SYSLOG, "enabling offsetting...");
	
	do_it = true;
}

__attribute__((destructor)) static 
void game_is_actually_over(int argc, const char **argv) {
	_syslog(LOG_SYSLOG, "todo");
}
