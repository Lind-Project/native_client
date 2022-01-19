
/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */


#ifndef NATIVE_CLIENT_SRC_INCLUDE_PERF_MAP_H_
#define NATIVE_CLIENT_SRC_INCLUDE_PERF_MAP_H_ 1

/*
 *   libperfmap: a JVM agent to create perf-<pid>.map files for consumption
 *               with linux perf-tools
 *   Copyright (C) 2013-2015 Johannes Rudolph<johannes.rudolph@gmail.com>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


void readelfandmap(char * elfpath, uintptr_t mem_start, FILE *method_file);
void create_perf_map(char * elfname, uintptr_t mem_start);
FILE *perf_map_open(pid_t pid);
int perf_map_close(FILE *fp);
void perf_map_write_entry(FILE *method_file, const void* code_addr, unsigned int code_size, const char* entry);


#endif  /* NATIVE_CLIENT_SRC_INCLUDE_PERF_MAP_H_ */
