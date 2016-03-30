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
 * library_injector.h
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

#ifndef mario_library_injector_h
#define mario_library_injector_h

#include <mach/mach_types.h>
#include <sys/types.h>
#include <sys/kernel.h>

kern_return_t inject_library(vm_map_t task_port, mach_vm_address_t base_address, char *path, int path_len);
kern_return_t inject_restricted(vm_map_t task_port, mach_vm_address_t base_address, char *path, int path_len);

#endif
