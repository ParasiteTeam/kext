/*
 * <-. (`-')   (`-')  _    (`-')   _
 *    \(OO )_  (OO ).-/ <-.(OO )  (_)         .->
 * ,--./  ,-.) / ,---.  ,------,) ,-(`-')(`-')----.
 * |   `.'   | | \ /`.\ |   /`. ' | ( OO)( OO).-.  '
 * |  |'.'|  | '-'|_.' ||  |_.' | |  |  )( _) | |  |
 * |  |   |  |(|  .-.  ||  .   .'(|  |_/  \|  |)|  |
 * |  |   |  | |  | |  ||  |\  \  |  |'->  '  '-'  '
 * `--'   `--' `--' `--'`--' '--' `--'      `-----'
 *
 * Mario - The kernel component to fix rootpipe
 *
 * This is a TrustedBSD kernel driver to inject a dynamic library
 * or a __RESTRICT segment into specific processes
 *
 * Copyright (c) fG!, 2015. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * kernel_symbols.h
 *
 * Functions to solve kernel symbols
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef mario_kernel_symbols_h
#define mario_kernel_symbols_h

#include <mach/mach_types.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/proc.h>

/* exported data structures */
struct kernel_info
{
    mach_vm_address_t memory_text_addr; // the address of __TEXT segment in kernel memory
    mach_vm_address_t disk_text_addr;    // the same address at /mach_kernel in filesystem
    mach_vm_address_t kaslr_slide;       // the kernel aslr slide, computed as the difference between above's addresses
    void *linkedit_buf;                  // pointer to __LINKEDIT buffer containing symbols to solve
    uint64_t linkedit_fileoff;           // __LINKEDIT file offset so we can read
                                         // WARNING: does not contain the fat offset value in case it's a FAT kernel
    uint64_t linkedit_size;
    uint32_t symboltable_fileoff;        // file offset to symbol table - used to position inside the __LINKEDIT buffer
    uint32_t symboltable_nr_symbols;
    uint32_t stringtable_fileoff;        // file offset to string table
    // other info from the header we might need
    uint64_t text_size;                  // size of __text section to disassemble
};

/* exported functions */
kern_return_t init_kernel_info(void);
kern_return_t cleanup_kernel_info(void);
kern_return_t solve_kernel_symbol(char *symbol_to_solve, void **symbol_ptr);

/* kernel symbols we will manually solve */
extern kern_return_t (*_vm_map_read_user)(vm_map_t map, vm_map_offset_t src_addr, void *dst_p, vm_size_t size);
extern kern_return_t (*_vm_map_write_user)(vm_map_t map, void *src_p, vm_map_address_t dst_addr, vm_size_t size);
extern kern_return_t (*_mach_vm_protect)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
extern vm_map_offset_t (*_get_map_min)(vm_map_t);
extern vm_map_t (*_get_task_map)(task_t);
extern kern_return_t (*_mach_vm_region)(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name);

#endif
