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
 * library_injector.c
 *
 * Functions to inject the library into userspace target
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

#include "library_injector.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/attr.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>
#include <kern/task.h>
#include <mach/mach_vm.h>
#include "kernel_symbols.h"
#include "config.h"
#include "logging.h"

/* local data structures */
struct header_info
{
    uint8_t is64bits;
    uint64_t aslr_slide;
    uint64_t linkedit_size;
    uint64_t linkedit_offset;
    mach_vm_address_t linkedit_addr;
    struct dyld_info_command *dyldinfo_cmd;
    struct symtab_command *symtab_cmd;
    uint32_t text_section_off;          /* location of __text section */
    uint32_t first_lib_offset;          /* offset of first dynamic library */
    uint32_t lib_count;                 /* number of linked dynamic libraries */
    uint32_t free_space;                /* free space in mach-o header for injection */
    uint8_t *linkedit_buf;              /* buffer that will hold __LINKED segment */
    mach_vm_address_t highestvmaddr;    /* highest vm addr in segment commands */
    uint64_t highestvmsize;
    uint32_t lowest_fileoff;            /* lowest data file offset to find out free header space */
    vm_map_t taskport;                  /* task port of the target binary */
};

/* local functions */
static vm_prot_t get_protection(vm_map_t task, mach_vm_address_t address);
static kern_return_t process_target_header(vm_map_t task_port, uint8_t *header, uint32_t header_size, mach_vm_address_t base_address, struct header_info *header_info);
static void find_lowest_offset(uint8_t *load_cmd_addr, struct header_info *header_info);
static kern_return_t write_user_mem(vm_map_t task_port, mach_vm_address_t target_addr, void* buf, uint32_t buf_len);
static kern_return_t inject_normal_method(uint8_t *header_buf, struct header_info *hi, mach_vm_address_t base_addr, uint32_t offset, struct dylib_command *cmd, char *lib_path);

/*
 * inject a dynamic library into the header
 */
kern_return_t
inject_library(vm_map_t task_port, mach_vm_address_t base_address, char *path, int path_len)
{
    char library_to_inject[MAXPATHLEN] = {0};
    /* verify is library to be injected exists in the filesystem */
    vnode_t lib_vnode = NULLVP;
    vfs_context_t libvfs_context = vfs_context_create(NULL);
    if (vnode_lookup(PATCH_LIBRARY, 0, &lib_vnode, libvfs_context))
    {
        LOG_ERROR("Library to be injected not found in filesystem! Please copy it to the configured path %s.", PATCH_LIBRARY);
        vfs_context_rele(libvfs_context);
        return KERN_FAILURE;
    }
    vnode_put(lib_vnode);
    vfs_context_rele(libvfs_context);
    /* set library to be injected to patch version */
    strlcpy(library_to_inject, PATCH_LIBRARY, sizeof(library_to_inject));
    
    kern_return_t kr = 0;
    struct header_info header_info = {0};
    /*
     * we need to read the header of the target process so we can find the injection space and modify it
     */
    struct mach_header_64 header = {0};
    kr = _vm_map_read_user(task_port, base_address, (void*)&header, sizeof(header));
    if (kr != KERN_SUCCESS)
    {
        LOG_ERROR("Couldn't read target mach-o header. error %x at address 0x%llx", kr, base_address);
        return KERN_FAILURE;
    }
    uint32_t header_size = sizeof(struct mach_header);
    switch (header.magic)
    {
        case MH_MAGIC_64:
            header_size = sizeof(struct mach_header_64);
            header_info.is64bits = 1;
            break;
        case MH_MAGIC:
            header_info.is64bits = 0;
            break;
        default:
            LOG_ERROR("Unknown header magic value %x!", header.magic);
            return KERN_FAILURE;
    }
    if (header.ncmds == 0 || header.sizeofcmds == 0)
    {
        LOG_ERROR("Bad ncmds or sizeofcmds!");
        return KERN_FAILURE;
    }
    
    /* calculate the buffer size we will need to hold the whole mach-o header */
    uint32_t total_header_size = header.sizeofcmds + header_size;
    uint8_t *full_header = _MALLOC(total_header_size, M_TEMP, M_WAITOK | M_ZERO);
    if (full_header == NULL)
    {
        LOG_ERROR("Can't allocate space for target full mach-o header!");
        return KERN_FAILURE;
    }
    /* copy the full header into our buffer */
    if (_vm_map_read_user(task_port, base_address, (void*)full_header, total_header_size))
    {
        LOG_ERROR("Can't read full target header!");
        goto failure;
    }

    header_info.lowest_fileoff = 0xFFFFFFFF;
    struct mach_header_64 *mh = (struct mach_header_64*)full_header;
    
    /* process the header and retrieve some information we will use */
    if (process_target_header(task_port, full_header, header_size, base_address, &header_info))
    {
        LOG_ERROR("Can't process mach-o header!");
        goto failure;
    }

    /* the injection position is after the last command */
    uint32_t injection_offset = mh->sizeofcmds + header_size; // overflow checked inside find_library_injection_space
    uint32_t libpath_len = (uint32_t)strlen(library_to_inject) + 1;
    /* prepare the LC_LOAD_DYLIB command to be injected */
    struct dylib_command newlib_cmd = {0};
    newlib_cmd.cmd = LC_LOAD_DYLIB;
    newlib_cmd.dylib.name.offset = 24;         // usually the name string is located just after the command
    newlib_cmd.dylib.timestamp = 0;
    newlib_cmd.dylib.current_version = 0;
    newlib_cmd.dylib.compatibility_version = 0;
    newlib_cmd.cmdsize = sizeof(struct dylib_command) + libpath_len;
    /* cmdsize must be a multiple of uint32_t */
    uint32_t remainder = ( sizeof(struct dylib_command) + libpath_len ) % sizeof(uint32_t);
    if (remainder != 0)
    {
        newlib_cmd.cmdsize += sizeof(uint32_t) - remainder;
    }
    if (header_info.free_space < newlib_cmd.cmdsize)
    {
        LOG_ERROR("Not enough space to inject library at %s!", path);
    }
    else
    {
        if (inject_normal_method(full_header, &header_info, base_address, injection_offset, &newlib_cmd, library_to_inject))
        {
            goto failure;
        }
    }
    
success:
    _FREE(full_header, M_TEMP);
    full_header = NULL;
    _FREE(header_info.linkedit_buf, M_TEMP);
    header_info.linkedit_buf = NULL;
    return KERN_SUCCESS;
failure:
    if (full_header)
    {
        _FREE(full_header, M_TEMP);
        full_header = NULL;
    }
    if (header_info.linkedit_buf)
    {
        _FREE(header_info.linkedit_buf, M_TEMP);
        header_info.linkedit_buf = NULL;
    }
    return KERN_FAILURE;
}

#pragma Local helper functions

/*
 * the normal method is to inject the LC_DYLIB_COMMAND at the start of the free space
 * and the string with path to the injected library after the command (24 bytes offset)
 */
static kern_return_t
inject_normal_method(uint8_t *header_buf, struct header_info *hi, mach_vm_address_t base_addr, uint32_t offset, struct dylib_command *cmd, char *lib_path)
{
    write_user_mem(hi->taskport, base_addr+offset, (void*)cmd, sizeof(struct dylib_command));
    write_user_mem(hi->taskport, base_addr+offset+sizeof(struct dylib_command), (void*)lib_path, (uint32_t)strlen(lib_path)+1);
    /*
     * if everything went ok above finally fix mach-o header
     * this is what enables the library because nr of commands are changed
     */
    struct mach_header_64 *mh = (struct mach_header_64*)header_buf;
    mh->ncmds += 1;
    mh->sizeofcmds += cmd->cmdsize;
    /* we could use mach_header_64 for both 32 and 64 since it holds the correct data */
    if (hi->is64bits)
    {
        write_user_mem(hi->taskport, base_addr, (void*)mh, sizeof(struct mach_header_64));
    }
    else
    {
        write_user_mem(hi->taskport, base_addr, (void*)mh, sizeof(struct mach_header));
    }
    return KERN_SUCCESS;
}

static kern_return_t
write_user_mem(vm_map_t task_port, mach_vm_address_t target_addr, void* buf, uint32_t buf_len)
{
    vm_prot_t orig_protection = get_protection(task_port, target_addr);
    /*
     * read current protection so we can restore it
     */
    if (_mach_vm_protect(task_port, target_addr, buf_len, FALSE, VM_PROT_WRITE | VM_PROT_READ))
    {
        LOG_ERROR("vm_protect to write injected library failed!");
        return KERN_FAILURE;
    }
    /* write the modified header to process */
    if (_vm_map_write_user(task_port, buf, target_addr, buf_len))
    {
        LOG_ERROR("write of modified header failed!");
        /* we want to try to protect again the memory segment else it will end real bad! */
    }
    /* restore original protection */
    if (_mach_vm_protect(task_port, target_addr, buf_len, FALSE, orig_protection))
    {
        /* XXX: this will leave application in a bad state. what to do here? */
        LOG_ERROR("vm_protect to original prot failed!");
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

/*
 * process the target mach-o header and retrieve all information we will need later on
 */
static kern_return_t
process_target_header(vm_map_t task_port, uint8_t *header, uint32_t header_size, mach_vm_address_t base_address, struct header_info *header_info)
{
    struct mach_header_64 *mh = (struct mach_header_64*)header;
    uint8_t lib_found = 0;
    if (UINT_MAX - mh->sizeofcmds < header_size)
    {
        LOG_ERROR("overflow?");
        return KERN_FAILURE;
    }
    if (mh->ncmds == 0 || mh->sizeofcmds == 0)
    {
        LOG_ERROR("Bad ncmds or sizeofcmds");
        return KERN_FAILURE;
    }

    /* find the last command offset */
    struct load_command *load_cmd = NULL;
    uint8_t *load_cmd_addr = (uint8_t*)header + header_size;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;
        /*
         * 64 bits segment commands
         */
        if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd_addr;
            if (seg_cmd->vmaddr > header_info->highestvmaddr)
            {
                header_info->highestvmaddr = seg_cmd->vmaddr;
                header_info->highestvmsize = seg_cmd->vmsize;
            }
            /* lookup this section to find out global lowest file offset */
            find_lowest_offset(load_cmd_addr, header_info);
            
            if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
            {
                // address of the first section
                uint8_t *section_addr = load_cmd_addr + sizeof(struct segment_command_64);
                for (uint32_t x = 0; x < seg_cmd->nsects; x++)
                {
                    struct section_64 *section_cmd = (struct section_64*)section_addr;
                    if (strncmp(section_cmd->sectname, "__text", 16) == 0)
                    {
                        header_info->text_section_off = section_cmd->offset;
                        break;
                    }
                    section_addr += sizeof(struct section_64);
                }
                /* the vmaddr value of __TEXT segment starts at the mach-o header location */
                /* base address is memory address where process is loaded */
                if (seg_cmd->vmaddr > base_address)
                {
                    LOG_ERROR("overflow?");
                    return KERN_FAILURE;
                }
                header_info->aslr_slide = base_address - seg_cmd->vmaddr;
            }
            else if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0)
            {
                header_info->linkedit_size      = seg_cmd->vmsize;
                header_info->linkedit_addr      = seg_cmd->vmaddr;
                header_info->linkedit_offset    = seg_cmd->fileoff;
            }
        }
        /*
         * all other commands we are interested in
         */
        /* find first location of a dynamic library */
        // XXX: test the other two commads!
        else if (load_cmd->cmd == LC_LOAD_DYLIB ||
                 load_cmd->cmd == LC_LOAD_WEAK_DYLIB ||
                 load_cmd->cmd == LC_REEXPORT_DYLIB)
        {
            if (lib_found == 0)
            {
                if ((uint32_t)header > (uint32_t)load_cmd_addr)
                {
                    LOG_ERROR("overflow?");
                    return KERN_FAILURE;
                }
                header_info->first_lib_offset = (uint32_t)(load_cmd_addr - header);
                lib_found = 1;
            }
            header_info->lib_count += 1;
        }
        else if (load_cmd->cmd == LC_SYMTAB)
        {
            header_info->symtab_cmd = (struct symtab_command*)load_cmd;
        }
        else if (load_cmd->cmd == LC_DYLD_INFO_ONLY)
        {
            header_info->dyldinfo_cmd = (struct dyld_info_command*)load_cmd;
        }
        /* other commands that have file offset information */
        else if (load_cmd->cmd == LC_ENCRYPTION_INFO)
        {
            struct encryption_info_command *tcmd = (struct encryption_info_command*)load_cmd;
            if ( tcmd->cryptoff != 0 && ( tcmd->cryptoff < header_info->lowest_fileoff) )
            {
                header_info->lowest_fileoff = tcmd->cryptoff;
            }
        }
        // advance to next command, size field holds the total size of each command, including sections
        load_cmd_addr += load_cmd->cmdsize;
    }
    /*
     * verify if there's enough free header space to inject the new command
     * between mach-o header + sizeofcmds and lowest data/code file offset
     * we found out the lowest file offset above so the difference between the two is the free header space
     */
    if ((mh->sizeofcmds + header_size) > header_info->lowest_fileoff)
    {
        LOG_ERROR("overflow?");
        return KERN_FAILURE;
    }
    header_info->free_space = header_info->lowest_fileoff - (mh->sizeofcmds + header_size);
    
    /* read whole __LINKEDIT */
    header_info->linkedit_buf = _MALLOC(header_info->linkedit_size, M_TEMP, M_WAITOK);
    if (header_info->linkedit_buf == NULL)
    {
        LOG_ERROR("Can't allocate buffer for __LINKEDIT!");
        return KERN_FAILURE;
    }
    if (_vm_map_read_user(task_port, header_info->linkedit_addr + header_info->aslr_slide, (void*)header_info->linkedit_buf, header_info->linkedit_size))
    {
        LOG_ERROR("Can't read __LINKEDIT from target!");
        /* free memory and return the pointer in a clean state */
        _FREE(header_info->linkedit_buf, M_TEMP);
        header_info->linkedit_buf = NULL;
        return KERN_FAILURE;
    }
    /* set the task port */
    header_info->taskport = task_port;

    return KERN_SUCCESS;
}

/*
 * aux function to find the lowest offset in mach-o header
 * its input is a LC_SEGMENT* command
 */
static void
find_lowest_offset(uint8_t *load_cmd_addr, struct header_info *header_info)
{
    /* 64 bits LC_SEGMENT_64 */
    struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd_addr;
    /* __TEXT segment usually has fileoff == 0 */
    /* iterate thru sections */
    /* XXX: how to deal with my section/segment anti-debug here ? */
    /* if segment fileoff is zero we should scan the sections */
    if (seg_cmd->fileoff == 0)
    {
        if (seg_cmd->nsects != 0)
        {
            uint8_t *section_addr = load_cmd_addr + sizeof(struct segment_command_64);
            for (uint32_t x = 0; x < seg_cmd->nsects; x++)
            {
                struct section_64 *section_cmd = (struct section_64*)section_addr;
                if (section_cmd->offset != 0 && section_cmd->offset < header_info->lowest_fileoff)
                {
                    header_info->lowest_fileoff = section_cmd->offset;
                }
                section_addr += sizeof(struct section_64);
            }
        }
    }
    /*
     * if segment fileoff is not zero, first test the segment and then sections if they exist
     */
    else
    {
        if (seg_cmd->fileoff < header_info->lowest_fileoff)
        {
            /* XXX: fileoff is uint64_t in LC_SEGMENT_64 */
            header_info->lowest_fileoff = (uint32_t)seg_cmd->fileoff;
        }
        if (seg_cmd->nsects != 0)
        {
            uint8_t *section_addr = load_cmd_addr + sizeof(struct segment_command_64);
            for (uint32_t x = 0; x < seg_cmd->nsects; x++)
            {
                struct section_64 *section_cmd = (struct section_64*)section_addr;
                /* there are sections with offset = 0, __common and __bss for example */
                if (section_cmd->offset != 0 && section_cmd->offset < header_info->lowest_fileoff)
                {
                    header_info->lowest_fileoff = section_cmd->offset;
                }
                section_addr += sizeof(struct section_64);
            }
        }
    }
}

#pragma mark Generic auxiliar functions

/*
 * retrieve the current memory protection flags of an address
 */
static vm_prot_t
get_protection(vm_map_t task_port, mach_vm_address_t address)
{
    if (task_port == NULL || address == 0)
    {
        LOG_ERROR("Bad parameters!");
        return -1;
    }
	vm_region_basic_info_data_64_t info = {0};
	mach_vm_size_t size = 0;
	mach_port_t object_name = 0;
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        
    if (_mach_vm_region(task_port, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object_name) != KERN_SUCCESS)
    {
        LOG_ERROR("get_protection failed!");
        return -1;
    }
	/* just return the protection field */
	return(info.protection);
}
