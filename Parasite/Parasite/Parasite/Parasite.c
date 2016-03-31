//
//  Parasite.c
//  Parasite
//
//  Created by Timm Kandziora on 01.03.16.
//  Copyright © 2016 Timm Kandziora. All rights reserved.
//

#include <mach/mach_port.h>
#include <libkern/libkern.h>
#include <sys/vnode.h>
#include <sys/kauth.h>
#include <kern/task.h>
#include <sys/proc.h>

#include "config.h"
#include "kernel_symbols.h"
#include "library_injector.h"

#define SOLVE_KERNEL_SYMBOL(string, pointer) if (solve_kernel_symbol((string), (void**)&(pointer))) { printf("Can't solve kernel symbol %s", (string)); return KERN_FAILURE;}

struct kernel_info g_kinfo;
static boolean_t kernel_symbols_solved = FALSE;

static boolean_t listener_initialized = FALSE;
static kauth_listener_t listener = NULL;

static int infection_overwatch(kauth_cred_t credential, void *idata, kauth_action_t action, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3)
{
    if (action == KAUTH_FILEOP_EXEC) {
        if (!kernel_symbols_solved) {
            if (init_kernel_info()) return 0;
            
            SOLVE_KERNEL_SYMBOL("_get_map_min", _get_map_min)
            SOLVE_KERNEL_SYMBOL("_get_task_map", _get_task_map)
            SOLVE_KERNEL_SYMBOL("_mach_vm_region", _mach_vm_region)
            SOLVE_KERNEL_SYMBOL("_mach_vm_protect", _mach_vm_protect)
            SOLVE_KERNEL_SYMBOL("_vm_map_read_user", _vm_map_read_user)
            SOLVE_KERNEL_SYMBOL("_vm_map_write_user", _vm_map_write_user)
            
            kernel_symbols_solved = TRUE;
        }
        
        char *path = (char *)arg1;
        
        printf("[Parasite] This bird is fly: %s.\n", path);
        
        if (!strcmp(path, "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock")) {
            vm_map_t task_map = _get_task_map(current_task());
            vm_map_offset_t base_address = _get_map_min(task_map);
            
            printf("[Parasite] Trying to inject library into %s.\n", path);
            
            if (inject_library(task_map, base_address, path, sizeof(path))) {
                printf("[Parasite] Failed to inject library into %s.\n", path);
            } else {
                printf("[Parasite] Successfully injected library into %s.\n", path);
            }
        }
    }
    
    return KAUTH_RESULT_DEFER;
}

kern_return_t Parasite_start(kmod_info_t *ki, void *d);
kern_return_t Parasite_stop(kmod_info_t *ki, void *d);

kern_return_t Parasite_start(kmod_info_t *ki, void *d)
{
    printf("[Parasite] Hello, I'm in memory.\n");
    
    if (listener_initialized == FALSE) {
        listener = kauth_listen_scope(KAUTH_SCOPE_FILEOP, &infection_overwatch, NULL);
        
        if (listener == NULL) {
            printf("[Parasite] Damn, could not create listener.\n");
        } else {
            printf("[Parasite] Successfully created listener.\n");
            listener_initialized = TRUE;
        }
    }
    
    return KERN_SUCCESS;
}

kern_return_t Parasite_stop(kmod_info_t *ki, void *d)
{
    if (listener != NULL) {
        kauth_unlisten_scope(listener);
        listener = NULL;
    }
    
    printf("[Parasite] Goodbye memory.\n");
    
    return KERN_SUCCESS;
}
