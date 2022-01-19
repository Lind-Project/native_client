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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#include "perf_map.h"

#define DEBUG_PATH "/home/lind/lind_project/lind/lindenv/debug"
#define DEBUG_PATH_LEN 8

void readelfandmap(char * elfpath, uintptr_t mem_start, FILE *method_file)
{
    Elf         *elf;
    Elf_Scn     *scn = NULL;
    GElf_Shdr   shdr;
    Elf_Data    *data;
    int         fd, ii, count;

    elf_version(EV_CURRENT);

    fd = open(elfpath, O_RDONLY);
    elf = elf_begin(fd, ELF_C_READ, NULL);

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);
        if (shdr.sh_type == SHT_SYMTAB) {
            /* found a symbol table, go print it. */
            break;
        }
    }

    data = elf_getdata(scn, NULL);
    count = shdr.sh_size / shdr.sh_entsize;

    /* print the symbol names */
    for (ii = 0; ii < count; ++ii) {
        GElf_Sym sym;
        gelf_getsym(data, ii, &sym);

        perf_map_write_entry(method_file, mem_start + sym.st_value, sym.st_size, elf_strptr(elf, shdr.sh_link, sym.st_name));
        printf("%d: ", ii);
        printf("name: %s   ", elf_strptr(elf, shdr.sh_link, sym.st_name));
        printf("addr: %x  ", sym.st_value);
        printf("size: %ld\n", sym.st_size);

    }
    elf_end(elf);
    close(fd);
}


void create_perf_map(char * elfname, uintptr_t mem_start) {

    pid_t nacl_pid = getpid();
    FILE* method_file = perf_map_open(nacl_pid);

    int elfpathsize = DEBUG_PATH_LEN + strlen(elfname) + 1;
    char* elfpath = calloc(elfpathsize, sizeof(char));
    snprintf(elfpath, elfpathsize, "%s%s", DEBUG_PATH, elfname);

    readelfandmap(elfpath, mem_start, method_file);

    perf_map_close(method_file);

}

FILE *perf_map_open(pid_t pid) {
    char filename[500];
    snprintf(filename, sizeof(filename), "/tmp/perf-%d.map", pid);
    FILE * res = fopen(filename, "w");
    if (!res) {
        fprintf(stderr, "Couldn't open %s: errno(%d)", filename, errno);
        exit(0);
    }
    return res;
}

int perf_map_close(FILE *fp) {
    if (fp)
        return fclose(fp);
    else
        return 0;
}

void perf_map_write_entry(FILE *method_file, const void* code_addr, unsigned int code_size, const char* entry) {
    if (method_file)
        fprintf(method_file, "%lx %x %s\n", (unsigned long) code_addr, code_size, entry);
}
