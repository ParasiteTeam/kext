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
 * kernel_symbols.c
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

#include "kernel_symbols.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/attr.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>

#include "config.h"
#include "logging.h"

/* global variables */
extern struct kernel_info g_kinfo;

/* kernel symbols to be manually solved */
vm_offset_t (*_vm_map_min)(vm_map_t map);
kern_return_t (*_vm_map_read_user)(vm_map_t map, vm_map_offset_t src_addr, void *dst_p, vm_size_t size);
kern_return_t (*_vm_map_write_user)(vm_map_t map, void *src_p, vm_map_address_t dst_addr, vm_size_t size);
kern_return_t (*_mach_vm_protect)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t (*_mach_vm_region)(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name);
vm_map_offset_t (*_get_map_min)(vm_map_t);
vm_map_t (*_get_task_map)(task_t);

/* local functions */
static kern_return_t get_kernel_mach_header(void *buffer, vnode_t kernel_vnode);
static kern_return_t process_kernel_mach_header(void *kernel_header, struct kernel_info *kinfo);
static kern_return_t get_kernel_linkedit(vnode_t kernel_vnode, struct kernel_info *kinfo);
static mach_vm_address_t calculate_int80address(const mach_vm_address_t idt_address);
static kern_return_t get_running_text_address(struct kernel_info *kinfo);
static mach_vm_address_t find_kernel_base(const mach_vm_address_t int80_address);
static kern_return_t get_addr_idt(mach_vm_address_t* idt);

/* 16 bytes IDT descriptor, used for 32 and 64 bits kernels (64 bit capable cpus!) */
struct descriptor_idt
{
	uint16_t offset_low;
	uint16_t seg_selector;
	uint8_t reserved;
	uint8_t flag;
	uint16_t offset_middle;
	uint32_t offset_high;
	uint32_t reserved2;
};

# pragma mark Exported functions

/*
 * entrypoint function to read necessary information from running kernel and kernel at disk
 * such as kaslr slide, linkedit location
 * the reads from disk are implemented using the available KPI VFS functions
 */
kern_return_t
init_kernel_info(void)
{
    struct kernel_info *kinfo = &g_kinfo;
    /* lookup vnode for /mach_kernel - remember to free reference count if successful */
    vnode_t kernel_vnode = NULLVP;
    /*
     * if we want to put the driver booting very early we need to create our own context
     * instead of passing NULL as usual
     * the reference count increases so we must release it later
     * the vfs_context_create() call is valid because it's made in a process context
     */
    vfs_context_t myvfs_context = vfs_context_create(NULL);
    if (myvfs_context == NULL)
    {
        LOG_ERROR("Failed to create context.");
        return KERN_FAILURE;
    }
    if (vnode_lookup(MACH_KERNEL, 0, &kernel_vnode, myvfs_context) != KERN_SUCCESS)
    {
        LOG_ERROR("Vnode lookup on %s failed!", MACH_KERNEL);
        return KERN_FAILURE;
    }
    /*
     * the first thing we do is to read 4k of the kernel header so we can extract
     * a bunch of information and __LINKEDIT location
     * we also must account for FAT kernels since we still target Lion
     */
    void *kernel_header = _MALLOC(PAGE_SIZE_64, M_TEMP, M_WAITOK | M_ZERO);
    if (kernel_header == NULL)
    {
        LOG_ERROR("Can't allocate memory for initial kernel mach-o header.");
        goto failure;
    }
    
    if (get_kernel_mach_header(kernel_header, kernel_vnode))
    {
        LOG_ERROR("Failed to get initial kernel mach-o header!");
        goto failure;
    }
    if (process_kernel_mach_header(kernel_header, kinfo))
    {
        LOG_ERROR("Failed to process kernel mach-o header!");
        goto failure;
    }
    
    /* compute kaslr slide - difference between __TEXT in memory and disk*/
    if (get_running_text_address(kinfo))
    {
        LOG_ERROR("Can't find kernel's running text address!");
        goto failure;
    }
    kinfo->kaslr_slide = kinfo->memory_text_addr - kinfo->disk_text_addr;
    if (kinfo->kaslr_slide > kinfo->memory_text_addr)
    {
        LOG_ERROR("overflow?");
        goto failure;
    }
//    LOG_DEBUG("kernel aslr slide is 0x%llx", kinfo->kaslr_slide);
    /*
     * we know the location of linkedit and offsets into symbols and their strings
     * now we need to read linkedit into a buffer so we can process it later
     * __LINKEDIT total size is around 1MB
     * we should free this buffer later when we don't need anymore to solve symbols
     * the fat_offset is passed so the offset is correct in case it's a FAT kernel
     */
    kinfo->linkedit_buf = _MALLOC(kinfo->linkedit_size, M_TEMP, M_WAITOK | M_ZERO);
    if (kinfo->linkedit_buf == NULL)
    {
        LOG_ERROR("Could not allocate enough memory for __LINKEDIT segment");
        goto failure;
    }
    if (get_kernel_linkedit(kernel_vnode, kinfo))
    {
        LOG_ERROR("Failed to get kernel linkedit info!");
        goto failure;
    }
    
success:
    /* kernel_header is a local buffer so we can get rid of it */
    _FREE(kernel_header, M_TEMP);
    kernel_header = NULL;
    /*
     * drop the iocount due to vnode_lookup()
     * we must do this else machine will block on shutdown/reboot
     */
    vnode_put(kernel_vnode);
    vfs_context_rele(myvfs_context);
    return KERN_SUCCESS;
    
failure:
    if (kinfo->linkedit_buf)
    {
        _FREE(kinfo->linkedit_buf, M_TEMP);
        kinfo->linkedit_buf = NULL;
    }
    if (kernel_header)
    {
        _FREE(kernel_header, M_TEMP);
        kernel_header = NULL;
    }
    vnode_put(kernel_vnode);
    vfs_context_rele(myvfs_context);
    return KERN_FAILURE;
}

/*
 * cleanup the kernel info buffer to avoid memory leak.
 * there's nothing else to cleanup here, for now
 */
kern_return_t
cleanup_kernel_info(void)
{
    if (g_kinfo.linkedit_buf)
    {
        _FREE(g_kinfo.linkedit_buf, M_TEMP);
    }
    return KERN_SUCCESS;
}

/*
 * function to solve a kernel symbol
 */
kern_return_t
solve_kernel_symbol(char *symbol_to_solve, void **symbol_ptr)
{
    struct kernel_info *kinfo = &g_kinfo;
    struct nlist_64 *nlist = NULL;
    LOG_DEBUG("Trying to solve kernel symbol %s...", symbol_to_solve);
    if (kinfo == NULL || kinfo->linkedit_buf == NULL)
    {
        LOG_ERROR("g_kernel_info is null or no kernel __LINKEDIT buffer available!");
        return 0;
    }
    // symbols and strings offsets into LINKEDIT
    // we just read the __LINKEDIT but fileoff values are relative to the full /mach_kernel
    // subtract the base of LINKEDIT to fix the value into our buffer
    mach_vm_address_t symbol_off = kinfo->symboltable_fileoff - kinfo->linkedit_fileoff;
    mach_vm_address_t string_off = kinfo->stringtable_fileoff - kinfo->linkedit_fileoff;
    if (symbol_off > kinfo->symboltable_fileoff || string_off > kinfo->stringtable_fileoff)
    {
        LOG_ERROR("bad offsets.");
        return KERN_FAILURE;
    }

    // search for the symbol and get its location if found
    for (uint32_t i = 0; i < kinfo->symboltable_nr_symbols; i++)
    {
        // get the pointer to the symbol entry and extract its symbol string
        nlist = (struct nlist_64*)((char*)kinfo->linkedit_buf + symbol_off + i * sizeof(struct nlist_64));
        char *symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist->n_un.n_strx);
        // find if symbol matches
        if (strncmp(symbol_to_solve, symbol_string, strlen(symbol_to_solve)) == 0)
        {
            //LOG_DEBUG("found symbol %s at 0x%llx (non-aslr 0x%llx)", symbol_to_solve, nlist->n_value + kinfo->kaslr_slide, nlist->n_value);
            /* the symbols values are without kernel ASLR so we need to add it */
            mach_vm_address_t solved_addr = nlist->n_value + kinfo->kaslr_slide;
            /* verify if symbol is in the kernel __text section */
            mach_vm_address_t floor = kinfo->memory_text_addr;
            mach_vm_address_t cap = kinfo->memory_text_addr + kinfo->text_size;
            if (solved_addr < floor || solved_addr > cap)
            {
                LOG_ERROR("Solved symbol address doesn't belong to running __text section. Something is wrong!");
                return KERN_FAILURE;
            }
            *symbol_ptr = (void*)solved_addr;
            return KERN_SUCCESS;
        }
    }
    /* failure */
    LOG_ERROR("Failed to solve symbol %s", symbol_to_solve);
    return KERN_FAILURE;
}

#pragma mark Internal helper functions

/*
 * retrieve the first page of kernel binary at disk into a buffer
 * version that uses KPI VFS functions and a ripped uio_createwithbuffer() from XNU
 * the buffer always end with a 64 bits kernel or error
 */
static kern_return_t
get_kernel_mach_header(void *buffer, vnode_t kernel_vnode)
{
    if (buffer == NULL || kernel_vnode == NULLVP)
    {
        LOG_ERROR("Bad arguments.");
        return KERN_FAILURE;
    }
    
    int error = 0;
    
    uio_t uio = NULL;
    uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
    if (uio == NULL)
    {
        LOG_ERROR("uio_create returned null!");
        return KERN_FAILURE;
    }
    // imitate the kernel and read a single page from the header
    if ( (error = uio_addiov(uio, CAST_USER_ADDR_T(buffer), PAGE_SIZE_64)) )
    {
        LOG_ERROR("uio_addiov returned error %d!", error);
        return KERN_FAILURE;
    }
    
    vfs_context_t context = vfs_context_create(NULL);
    if (context == NULL)
    {
        LOG_ERROR("Failed to create context.");
        return KERN_FAILURE;
    }
    // read kernel vnode into the buffer
    if ( (error = VNOP_READ(kernel_vnode, uio, 0, context)) )
    {
        LOG_ERROR("VNOP_READ failed %d!", error);
        vfs_context_rele(context);
        return KERN_FAILURE;
    }
    else if (uio_resid(uio))
    {
        LOG_ERROR("uio_resid!");
        vfs_context_rele(context);
        return KERN_FAILURE;
    }
    
    vfs_context_rele(context);
    return KERN_SUCCESS;
}

/*
 * retrieve the whole linkedit segment into target buffer from kernel binary at disk
 * we keep this buffer until we don't need to solve symbols anymore
 */
static kern_return_t
get_kernel_linkedit(vnode_t kernel_vnode, struct kernel_info *kinfo)
{
    if (kernel_vnode == NULLVP || kinfo == NULL)
    {
        LOG_ERROR("Bad arguments.");
        return KERN_FAILURE;
    }
    
    int error = 0;
    uio_t uio = uio_create(1, kinfo->linkedit_fileoff, UIO_SYSSPACE, UIO_READ);
    if (uio == NULL)
    {
        LOG_ERROR("uio_create returned null!");
        return KERN_FAILURE;
    }
    if ( (error = uio_addiov(uio, CAST_USER_ADDR_T(kinfo->linkedit_buf), kinfo->linkedit_size)) )
    {
        LOG_ERROR("uio_addiov returned error %d!", error);
        return KERN_FAILURE;
    }
    
    vfs_context_t context = vfs_context_create(NULL);
    if (context == NULL)
    {
        LOG_ERROR("Failed to create context.");
        return KERN_FAILURE;
    }
    if ( (error = VNOP_READ(kernel_vnode, uio, 0, context)) )
    {
        LOG_ERROR("VNOP_READ failed %d!", error);
        vfs_context_rele(context);
        return KERN_FAILURE;
    }
    else if (uio_resid(uio))
    {
        LOG_ERROR("uio_resid!");
        vfs_context_rele(context);
        return KERN_FAILURE;
    }
    
    vfs_context_rele(context);
    return KERN_SUCCESS;
}

/*
 * retrieve necessary mach-o header information from the kernel buffer
 * stored at our kernel_info structure
 * XXX: we only process 64 bits kernels
 */
static kern_return_t
process_kernel_mach_header(void *kernel_header, struct kernel_info *kinfo)
{
    if (kernel_header == NULL || kinfo == NULL)
    {
        LOG_ERROR("Invalid arguments.");
        return KERN_FAILURE;
    }
    
    struct mach_header_64 *mh = (struct mach_header_64*)kernel_header;
    if (mh->magic != MH_MAGIC_64)
    {
        LOG_ERROR("Kernel is not 64bits!");
        return KERN_FAILURE;
    }
    if (mh->ncmds == 0 || mh->sizeofcmds == 0)
    {
        LOG_ERROR("Invalid nr of commands or size.");
        return KERN_FAILURE;
    }
    
    struct load_command *load_cmd = NULL;
    /* point to the first load command */
    char *load_cmd_addr = (char*)kernel_header + sizeof(struct mach_header_64);
    /* iterate over all load cmds and retrieve required info to solve symbols */
    /* __LINKEDIT location and symbol/string table location */
    int found_linkedit = 0;
    int found_symtab = 0;
    int found_text = 0;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;
        if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
            /* use this one to retrieve the original vm address of __TEXT so we can compute kernel aslr slide */
            if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
            {
                kinfo->disk_text_addr = seg_cmd->vmaddr;
                /* lookup the __text section - we want the size which can be retrieve here or from the running version */
                char *section_addr = load_cmd_addr + sizeof(struct segment_command_64);
                for (uint32_t x = 0; x < seg_cmd->nsects; x++)
                {
                    struct section_64 *section_cmd = (struct section_64*)section_addr;
                    if (strncmp(section_cmd->sectname, "__text", 16) == 0)
                    {
                        kinfo->text_size = section_cmd->size;
                        found_text++;
                        break;
                    }
                    section_addr += sizeof(struct section_64);
                }
            }
            else if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0)
            {
                kinfo->linkedit_fileoff = seg_cmd->fileoff;
                kinfo->linkedit_size    = seg_cmd->filesize;
                found_linkedit++;
            }
        }
        /* table information available at LC_SYMTAB command */
        else if (load_cmd->cmd == LC_SYMTAB)
        {
            struct symtab_command *symtab_cmd = (struct symtab_command*)load_cmd;
            kinfo->symboltable_fileoff    = symtab_cmd->symoff;
            kinfo->symboltable_nr_symbols = symtab_cmd->nsyms;
            kinfo->stringtable_fileoff    = symtab_cmd->stroff;
            found_symtab++;
        }
        load_cmd_addr += load_cmd->cmdsize;
    }
    
    /* validate if we got all info we need */
    if (found_linkedit == 0 || found_symtab == 0 || found_text == 0)
    {
        LOG_ERROR("Failed to find all necessary kernel mach-o header info.");
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
}

/*
 * retrieve the __TEXT address of current loaded kernel so we can compute the KASLR slide
 * also the size of __text
 * XXX: only processing 64 bits kernels!
 */
static kern_return_t
get_running_text_address(struct kernel_info *kinfo)
{
    if (kinfo == NULL)
    {
        LOG_ERROR("Bad parameter!");
        return KERN_FAILURE;
    }
    
    /* retrieves the address of the IDT */
    mach_vm_address_t idt_address = 0;
    if (get_addr_idt(&idt_address) != KERN_SUCCESS)
    {
        return KERN_FAILURE;
    }
    /* calculate the address of the int80 handler */
    mach_vm_address_t int80_address = calculate_int80address(idt_address);
    /* search backwards for the kernel base address (mach-o header) */
    mach_vm_address_t kernel_base = find_kernel_base(int80_address);
    if (kernel_base != 0)
    {
        /* get the vm address of __TEXT segment */
        struct mach_header_64 *mh = (struct mach_header_64*)kernel_base;
        struct load_command *load_cmd = NULL;
        char *load_cmd_addr = (char*)kernel_base + sizeof(struct mach_header_64);
        for (uint32_t i = 0; i < mh->ncmds; i++)
        {
            load_cmd = (struct load_command*)load_cmd_addr;
            if (load_cmd->cmd == LC_SEGMENT_64)
            {
                struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
                if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
                {
                    kinfo->memory_text_addr = seg_cmd->vmaddr;
                    return KERN_SUCCESS;
                }
            }
            load_cmd_addr += load_cmd->cmdsize;
        }
    }
    return KERN_FAILURE;
}

/* calculate the address of the kernel int80 handler using the IDT array */
static mach_vm_address_t
calculate_int80address(const mach_vm_address_t idt_address)
{
    if (idt_address == 0)
    {
        LOG_ERROR("Bad parameter!");
        return 0;
    }
  	/* find the address of interrupt 0x80 - EXCEP64_SPC_USR(0x80,hi64_unix_scall) @ osfmk/i386/idt64.s */
	struct descriptor_idt *int80_descriptor = NULL;
	mach_vm_address_t int80_address = 0;
    // we need to compute the address, it's not direct
    // extract the stub address
    // retrieve the descriptor for interrupt 0x80
    // the IDT is an array of descriptors
    int80_descriptor = (struct descriptor_idt*)(idt_address+sizeof(struct descriptor_idt)*0x80);
    uint64_t high = (unsigned long)int80_descriptor->offset_high << 32;
    uint32_t middle = (unsigned int)int80_descriptor->offset_middle << 16;
    int80_address = (mach_vm_address_t)(high + middle + int80_descriptor->offset_low);
	//LOG_DEBUG("Address of interrupt 80 stub is 0x%llx", int80_address);
    return int80_address;
}

/*
 * find the kernel base address (mach-o header)
 * by searching backwards using the int80 handler as starting point
 */
static mach_vm_address_t
find_kernel_base(const mach_vm_address_t int80_address)
{
    if (int80_address == 0)
    {
        LOG_ERROR("Bad parameter!");
        return 0;
    }
    mach_vm_address_t temp_address = int80_address;
    struct segment_command_64 *segment_command = NULL;
    struct mach_header_64 *mh = NULL;
    while (temp_address > 0)
    {
        mh = (struct mach_header_64*)temp_address;
        if (mh->magic == MH_MAGIC_64 &&
            mh->filetype == MH_EXECUTE &&
            mh->ncmds > 0 &&
            mh->sizeofcmds > 0)
        {
            /* make sure it's the header and not some reference to the MAGIC number */
            segment_command = (struct segment_command_64*)(temp_address + sizeof(struct mach_header_64));
            if (strncmp(segment_command->segname, "__TEXT", 16) == 0)
            {
                //LOG_DEBUG("Found running kernel mach-o header address at %p", (void*)(temp_address));
                return temp_address;
            }
        }
        /* check for int overflow */
        if (temp_address - 1 > temp_address)
        {
            break;
        }
        temp_address--;
    }
    return 0;
}

/* retrieve the address of the IDT */
static kern_return_t
get_addr_idt(mach_vm_address_t *idt)
{
    if (idt == NULL)
    {
        LOG_ERROR("Bad parameter!");
        return KERN_FAILURE;
    }
    
	uint8_t idtr[10];
	__asm__ volatile ("sidt %0": "=m" (idtr));
	*idt = *(mach_vm_address_t *)(idtr+2);
    return KERN_SUCCESS;
}
