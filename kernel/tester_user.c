// Standard libraries
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>

// Syscalls
#include <fcntl.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <getopt.h>

// Raise limits
#include <sys/resource.h>

// Libbpf
#include "tester_user.h"

static ebpf_specify_name_t dc_optional_name[] = { {.program_name = "netdata_lookup_fast",
                                                   .function_to_attach = "lookup_fast",
                                                   .optional = NULL,
                                                   .retprobe = 0},
                                                  {.program_name = NULL}};

// Versions 3_10, 4_18 and 5_14 must be always present to keep compatibility with RH family
// Version 4_14, 4_16 must be present for syscalls with old name convention
// Version 5_4 must be present for kernels newer than 4.17.0
ebpf_module_t ebpf_modules[] = {
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_10 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_BTRFS, .name = "btrfs", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_15 | NETDATA_V5_14 | NETDATA_V5_16,
      .flags = NETDATA_FLAG_CACHESTAT, .name = "cachestat", .update_names = NULL, .ctrl_table = "cstat_ctrl" },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_DC, .name = "dc", .update_names = dc_optional_name, .ctrl_table = "dcstat_ctrl" },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_DISK, .name = "disk", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_EXT4, .name = "ext4", .update_names = NULL, .ctrl_table = "ext4_ctrl" },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_11 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_FD, .name = "fd", .update_names = NULL, .ctrl_table = "fd_ctrl" },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_SYNC, .name = "fdatasync", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_SYNC, .name = "fsync", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_HARDIRQ, .name = "hardirq", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_MDFLUSH, .name = "mdflush", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_MOUNT, .name = "mount", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_SYNC, .name = "msync", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_NFS, .name = "nfs", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_OOMKILL, .name = "oomkill", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14 | NETDATA_V5_10,
      .flags = NETDATA_FLAG_PROCESS, .name = "process", .update_names = NULL, .ctrl_table = "process_ctrl" },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_SHM, .name = "shm", .update_names = NULL, .ctrl_table = "shm_ctrl" },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_SOCKET, .name = "socket", .update_names = NULL, .ctrl_table = "socket_ctrl" },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_SOFTIRQ, .name = "softirq", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_SYNC, .name = "sync", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_SYNC, .name = "syncfs", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_SYNC, .name = "sync_file_range", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_SWAP, .name = "swap", .update_names = NULL, .ctrl_table = "swap_ctrl" },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_VFS, .name = "vfs", .update_names = NULL, .ctrl_table = "vfs_ctrl" },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_XFS, .name = "xfs", .update_names = NULL, .ctrl_table = NULL },
    { .kernels =  NETDATA_V3_10 | NETDATA_V4_14 | NETDATA_V4_16 | NETDATA_V4_18 | NETDATA_V5_4 | NETDATA_V5_14,
      .flags = NETDATA_FLAG_ZFS, .name = "zfs", .update_names = NULL, .ctrl_table = NULL },

    { .kernels = 0, .name = NULL, .update_names = NULL }
};

char *specific_ebpf = NULL;
char *netdata_path = NULL;
char *log_path = NULL;
#define NETDATA_DEFAULT_PROCESS_NUMBER 4096
long nprocesses;
FILE *stdlog = NULL;
int end_iteration = 1;
enum netdata_apps_level map_level = NETDATA_APPS_LEVEL_REAL_PARENT ;

/****************************************************************************************************
 *
 *                                      KERNEL VERSION
 *
 ***************************************************************************************************/

/**
 * Get kernel version
 *
 * Get kernel from host parsing osrelease
 *
 * @return It returns the kernel version on success and -1 otherwise.
 */
int ebpf_get_kernel_version()
{
    char major[16], minor[16], patch[16];
    char ver[VERSION_STRING_LEN];
    char *version = ver;

    int fd = open("/proc/sys/kernel/osrelease", O_RDONLY);
    if (fd < 0)
        return -1;

    ssize_t len = read(fd, ver, sizeof(ver));
    if (len < 0) {
        close(fd);
        return -1;
    }

    close(fd);

    char *move = major;
    while (*version && *version != '.')
        *move++ = *version++;
    *move = '\0';

    version++;
    move = minor;
    while (*version && *version != '.')
        *move++ = *version++;
    *move = '\0';

    if (*version)
        version++;
    else
        return -1;

    move = patch;
    while (*version && *version != '\n' && *version != '-')
        *move++ = *version++;
    *move = '\0';

    return ((int)(strtol(major, NULL, 10) * 65536) + (int)(strtol(minor, NULL, 10) * 256) + (int)strtol(patch, NULL, 10));
}

/**
 * Red Hat Release
 *
 * Get current Red Hat release.
 *
 * Red Hat has kernels from kernel.org with patches applied, so its kernel version has features present
 * in newer kernels.
 *
 * @param return It returns the Red Hat version on success and -1 otherwise.
 */
int ebpf_get_redhat_release()
{
    char buffer[VERSION_STRING_LEN + 1];
    int major, minor;
    FILE *fp = fopen("/etc/redhat-release", "r");

    if (fp) {
        major = 0;
        minor = -1;
        size_t length = fread(buffer, sizeof(char), VERSION_STRING_LEN, fp);
        if (length > 4) {
            buffer[length] = '\0';
            char *end = strchr(buffer, '.');
            char *start;
            if (end) {
                *end = 0x0;

                if (end > buffer) {
                    start = end - 1;

                    major = strtol(start, NULL, 10);
                    start = ++end;

                    end++;
                    if (end) {
                        end = 0x00;
                        minor = strtol(start, NULL, 10);
                    } else {
                        minor = -1;
                    }
                }
            }
        }

        fclose(fp);
        return ((major * 256) + minor);
    } else {
        return -1;
    }
}

/**
 * Kernel Name
 *
 * Select kernel name used by eBPF programs
 *
 * Netdata delivers for users eBPF programs with specific suffixes that represent the kernels they were
 * compiled, when we load the eBPF program, the suffix must be the nereast possible of the kernel running.
 *
 * @param selector select the kernel version.
 *
 * @return It returns the string to load kernel.
 */
static char *ebpf_select_kernel_name(uint32_t selector)
{
    static char *kernel_names[] = { "3.10", "4.14", "4.16", "4.18", "5.4", "5.10", "5.11", "5.14", "5.15", "5.16" };

    return kernel_names[selector];
}

/**
 * Select Max Index
 *
 * Select last index that will be tested on host.
 *
 * @param rhf_version is Red Hat family?
 * @param kver        the kernel version
 *
 * @return it returns the index to access kernel string.
 */
static int ebpf_select_max_index(int rhf_version, uint32_t kver)
{
    if (rhf_version > 0) { // Red Hat family
        if (kver >= NETDATA_EBPF_KERNEL_5_14)
            return 7;
        else if (kver >= NETDATA_EBPF_KERNEL_5_4) 
            return 4;
        else if (kver >= NETDATA_EBPF_KERNEL_4_11)
            return 3;
    } else { // Kernels from kernel.org
        if (kver >= NETDATA_EBPF_KERNEL_5_16)
            return 9;
        else if (kver >= NETDATA_EBPF_KERNEL_5_15)
            return 8;
        else if (kver >= NETDATA_EBPF_KERNEL_5_11)
            return 6;
        else if (kver >= NETDATA_EBPF_KERNEL_5_10)
            return 5;
        else if (kver >= NETDATA_EBPF_KERNEL_4_17)
            return 4;
        else if (kver >= NETDATA_EBPF_KERNEL_4_15)
            return 2;
        else if (kver >= NETDATA_EBPF_KERNEL_4_11)
            return 1;
    }

    return 0;
}

/**
 * Select Index
 *
 * Select index to load data.
 *
 * @param kernels      is the variable with kernel versions.
 * @param rhf_version  is Red Hat family?
 * param  kver         the kernel version
 */
static uint32_t ebpf_select_index(uint32_t kernels, int rhf_version, uint32_t kver)
{
    uint32_t start = ebpf_select_max_index(rhf_version, kver);
    uint32_t idx;

    if (rhf_version == -1)
        kernels &= ~NETDATA_V5_14;

    for (idx = start; idx; idx--) {
        if (kernels & 1 << idx)
            break;
    }

    return idx;
}

/****************************************************************************************************
 *
 *                                      TESTS
 *
 ***************************************************************************************************/

/**
 * Start External JSON
 *
 * Writes the first lines for JSON message.
 */
static void ebpf_start_external_json(char *filename)
{
    fprintf(stdlog, "\n\"%s\" : {\n    \"Tables\" : {\n",
            filename);
}

/*
 * Start Netdata JSON
 *
 * Writes the first lines for JSON message when software is testing all eBPF programs delivered by Netdata.
 *
 * @param filename  the file to be tested.
 * @param is_return the file type.
 */
static void ebpf_start_netdata_json(char *filename, int is_return)
{
    static int first = 1;
    if (first) {
        first = 0;
        fprintf(stdlog, "\n");
    }
    fprintf(stdlog, "\"%s\" : {\n    \"Test\" : \"%s\",\n    \"Tables\" : {\n",
            filename, (is_return) ? "return" : "entry");
}

/**
 *  Mount Name
 *
 *  Mount name of eBPF program to be loaded. 
 *
 *  Netdata eBPF programs has the following format:
 * 
 *      Tnetdata_ebpf_N.V.o
 *  
 *  where:
 *     T - Is the eBPF type. When starts with 'p', this means we are only adding probes,
 *         and when they start with 'r' we are using retprobes.     
 *     N - The eBPF program name.
 *     V - The kernel version in string format.    
 *
 *  @param out            the vector where the name will be stored
 *  @param len            the size of the out vector.
 *  @param kver           the kernel version
 *  @param name           the eBPF program name.
 *  @param is_return      is return or entry ?
 *  @param rhf_version    Red Hat version.
 */
static void ebpf_mount_name(char *out, size_t len, uint32_t kver, char *name, int is_return, int rhf_version)
{
    char *version = ebpf_select_kernel_name(kver);
    char *path = (!netdata_path) ? getcwd(NULL, 0) : realpath(netdata_path, NULL);
    snprintf(out, len, "%s/%cnetdata_ebpf_%s.%s%s.o", 
            path,
            (is_return) ? 'r' : 'p',
            name,
            version,
            (rhf_version != -1) ? ".rhf" : "");
    free(path);
}

/**
 * Count programs
 *
 * Count the number of eBPF programs associated to the object 'obj'.
 *
 * @param obj the object loaded.
 *
 * @return It returns the number of programs available.
 */
size_t ebpf_count_programs(struct bpf_object *obj)
{
    size_t tot = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        tot++;
    }

    return tot;
}

/**
 * Find names
 *
 * Find name of the function among the list of names.
 *
 * This function is necessary, because depending of the parameters given during kernel compilation time,
 * a specific function can have different names, the main change is associated with prefixes or suffixes
 * appended to the function.
 *
 * @param names      list of names used to load specific tracers.
 * @param prog_name  the current program that I want to attach a tracer.
 *
 * @return It returns the name to be used on success and NULL otherwise
 */
static ebpf_specify_name_t *ebpf_find_names(ebpf_specify_name_t *names, const char *prog_name)
{
    size_t i = 0;
    while (names[i].program_name) {
        if (!strcmp(prog_name, names[i].program_name))
            return &names[i];

        i++;
    }

    return NULL;
}

/**
 * Attach programs
 * 
 * Attach eBPF programs to specified target.
 *
 * When we load an eBPF program in memory, it still needs to be associated with a target where it will collect data,
 * this function attaches all eBPF programs to its targets.
 *
 * @param load   output structure to store pointer for allocated links and number of success and fails.
 * @param obj    object with eBPF program information.
 * @param total  number of targets.
 * @param names    vector with names to modify target.
 *
 * @return It returns 0 on success and -1 otherwise.
 */
static int ebpf_attach_programs(ebpf_attach_t *load, struct bpf_object *obj, size_t total, ebpf_specify_name_t *names)
{
    load->links = calloc(total , sizeof(struct bpf_link *));
    if (!load->links)
        return -1;

    struct bpf_link **links = load->links;
    size_t i = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj)
    {
        ebpf_specify_name_t *w;
        if (names) {
            const char *name = bpf_program__name(prog);
            w = ebpf_find_names(names, name);
        } else
            w = NULL;

        if (w) {
            enum bpf_prog_type type = bpf_program__get_type(prog);
            if (type == BPF_PROG_TYPE_KPROBE)
                links[i] = bpf_program__attach_kprobe(prog, w->retprobe, w->optional);
        } else
            links[i] = bpf_program__attach(prog);

        if (libbpf_get_error(links[i])) {
            links[i] = NULL;
        } else
            i++;

    }

    load->success  = i;
    load->fail = total - i;

    return 0;
}

/**
 * Update names
 *
 * Open /proc/kallsyms and update the name for specific function
 *
 * @param names    vector with names to modify target.
 */
static void ebpf_update_names(ebpf_specify_name_t *names)
{
    if (names->optional)
        return;

    char line[256];
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp)
        return;

    char *data;
    char *cmp = names->function_to_attach;
    size_t len = strlen(cmp);
    while ( (data = fgets(line, 255, fp))) {
        data += 19;
        ebpf_specify_name_t *move = names;
        if (!strncmp(cmp, data, len)) {
            char *end = strchr(data, ' ');
            if (!end)
                end = strchr(data, '\n');

            if (end)
                *end = '\0';

            names->optional = strdup(data);
            break;
        }
    }

    fclose(fp);
}

/**
 * Clean Optional
 *
 * Clean all optional names allocated .
 *
 * @param names are the names that we need to clean
 */
static void ebpf_clean_optional(ebpf_specify_name_t *names)
{
    int i = 0;
    while (names[i].function_to_attach) {
        if (names[i].optional)
            free(names[i].optional);

        i++;
    }
}

/**
 * Cleanup tables
 *
 * Clean allocated values.
 *
 * @param out is the structure with addresses to clean.
 */
static void ebpf_cleanup_tables(ebpf_table_data_t *out)
{
    if (!out)
        return;

    if (out->key) 
        free(out->key);

    if (out->next_key)
        free(out->next_key);

    if (out->value)
        free(out->value);

    if (out->def_value)
        free(out->def_value);

    free(out);
}

/**
 * Allocate tables
 *
 * Allocate values used to read data;
 *
 * @param name   the table name.
 * @param key    the size of the key.
 * @param value  the size of the values.
 */
static ebpf_table_data_t *ebpf_allocate_tables(const char *name, size_t key, size_t value)
{
    // We multiply value by number of proccess to avoid problems when data is stored
    // per process
    value *= nprocesses;

    ebpf_table_data_t *ret = calloc(1, sizeof(ebpf_table_data_t));
    if (!ret)
        return NULL;

    // Using `size_t` instead `char` to remove issues with Gentoo
    ret->key = calloc(key, sizeof(size_t));
    if (!ret->key)
        goto error_td;

    ret->next_key = calloc(key, sizeof(size_t));
    if (!ret->next_key)
        goto error_td;

    ret->value = calloc(value, sizeof(size_t));
    if (!ret->value)
        goto error_td;

    ret->def_value = calloc(value, sizeof(size_t));
    if (!ret->def_value)
        goto error_td;

    ret->key_length = key;
    ret->value_length = value;

    return ret;

error_td:
     fprintf(stderr, "Cannot allocate memory for table %s with pair of key=%lu and value=%lu\n", name, key, value);
     ebpf_cleanup_tables(ret);
     return NULL;
}

/**
 * Values Accumulator
 *
 * Count data not filled and filled.
 *
 * @param values is the structure where variables are set.
 */
static inline void ebpf_values_accumulator(ebpf_table_data_t *values)
{
    if (!memcmp(values->value, values->def_value, values->value_length))
        values->zero++;
    else
        values->filled++;
}

/**
 * Read Table
 *
 * Read values from specified table.
 *
 * @param values   structure to stored data.
 * @param fd       the file descriptor for the table.
 */
static void ebpf_read_generic_table(ebpf_table_data_t *values, int fd)
{
    size_t zero = 0;
    size_t filled = 0;

    // Reset completely the keys
    memset(values->key, 0, values->key_length);
    memset(values->next_key, 0, values->key_length);
    memset(values->value, 0, values->value_length);

    // Go trough all keys stored inside the eBPF maps
    while (!bpf_map_get_next_key(fd, values->key, values->next_key)) {
        if (!bpf_map_lookup_elem(fd, values->next_key, values->value)) {
            ebpf_values_accumulator(values);
        }

        // Copy the next key for the current key
        memcpy(values->key, values->next_key, values->key_length);

        memset(values->value, 0, values->value_length);
    }

    if (!bpf_map_lookup_elem(fd, values->key, values->value)) {
        ebpf_values_accumulator(values);
    }
}

/**
 * Write Common JSON vector
 *
 * Write report for a specific table.
 *
 * @param values the vector with information read from table.
 * @param fd     the file descriptor to get data.
 */
static void ebpf_write_common_json_vector(ebpf_table_data_t *values, int fd)
{
    int i;
    // Read values from 
    for (i = 0; i < end_iteration; i++) {
       // Wait 5 seconds to fill table.
        sleep(5);

        // Get data from table
        ebpf_read_generic_table(values, fd);

        if (i)
            fprintf(stdlog, ",\n");

        // report
        fprintf(stdlog,
                "                                    "
                "{ \"Iteration\" :  %d, \"Total\" : %lu, \"Filled\" : %lu, \"Zero\" : %lu }",
                i, values->filled + values->zero, values->filled, values->zero); 
    }
    fprintf(stdlog, "\n");
}

/**
 * Controller JSON
 *
 * Write information from controller table in JSON format.
 *
 * We define 'specific information' as information per process, while we call 'global information', the inforamtion
 * related to simple calls.
 *
 * This controller table is a table used by Netdata to control the eBPF programs metrics. We use it to define
 * when eBPF programs need to collect specific information, when it is not filled, eBPF programs collect only
 * global data.
 *
 * @param values the vector with information read from table.
 * @param fd     the file descriptor to get data.
 */
static void ebpf_controller_json(ebpf_table_data_t *values, int fd)
{
    uint32_t value = 0;
    uint32_t zero = 0; 

    uint32_t key, read[nprocesses];
    for (key = 0; key < NETDATA_CONTROLLER_END; key++) {
        if (bpf_map_lookup_elem(fd, &key, read)) {
            zero++;
        } else {
            value++;
        }
    }
    fprintf(stdlog,
            "                                    "
            "{ \"Iteration\" : 1, \"Total\" : %u, \"Filled\" : %u, \"Zero\" : %d }\n",
            value + zero,  value, zero); 
}

/**
 * Test Maps
 *
 * Test all maps for an eBPF program
 *
 * @param obj  the object loaded.
 * @param ctrl the name of control table
 */
static void ebpf_test_maps(struct bpf_object *obj, char *ctrl)
{
    struct bpf_map *map;

    int tables = 0;
    // Loop trough all maps
    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        int fd = bpf_map__fd(map);
        ebpf_table_data_t *values;
        uint32_t key_size;
        uint32_t value_size;
#ifdef LIBBPF_MAJOR_VERSION
        enum bpf_map_type type = bpf_map__type(map);

        key_size = bpf_map__key_size(map);
        value_size = bpf_map__value_size(map);
#else
        const struct bpf_map_def *def = bpf_map__def(map);
        int type = def->type;
        key_size = def->key_size;
        value_size = def->value_size;
#endif
        values = ebpf_allocate_tables(name, key_size, value_size);
        if (values) {
            // Write header
           fprintf(stdlog,
                   "        \"%s\" : {\n            \"Info\" : { \"Length\" : { \"Key\" : %u, \"Value\" : %u},\n"
                   "                       \"Type\" : %u,\n"
                   "                       \"FD\" : %d,\n" 
                   "                       \"Data\" : [\n",
                   name, key_size, value_size, type, fd);

           // Read data and fill vector
            if (!ctrl || (ctrl && (strcmp(ctrl, name)))) {
                ebpf_write_common_json_vector(values, fd);
            } else {
                ebpf_controller_json(values, fd);
            }

            // Close JSON vector and object
            fprintf(stdlog, "                                ]\n"
                   "                      }\n" 
                   "        },\n");

            tables++;

            ebpf_cleanup_tables(values);
        }
    }

    // Write total tables read
    if (tables) {
        fprintf(stdlog, "        \"Total tables\" : %d\n", tables);
    }
}

/**
 * Fill Control table 
 *
 * Fill control table with data allowing eBPF collectors to store specific data.
 *
 * @param obj the object loaded.
 * @param ctrl is the control table name.
 */
static void ebpf_fill_ctrl(struct bpf_object *obj, char *ctrl)
{
    struct bpf_map *map;

    bpf_object__for_each_map(map, obj) {
        // We only few datas fro the controller
        const char *name = bpf_map__name(map);
        if (strcmp(name, ctrl))
            continue;

        int fd = bpf_map__fd(map);

        unsigned int i, end;
#ifdef LIBBPF_MAJOR_VERSION
        end = bpf_map__max_entries(map);
#else
        const struct bpf_map_def *def = bpf_map__def(map);
        end = def->max_entries;
#endif
        uint32_t values[NETDATA_CONTROLLER_END] = { 1, map_level};
        for (i = 0; i < end; i++) {
             int ret = bpf_map_update_elem(fd, &i, &values[i], 0);
             if (ret)
                 fprintf(stdlog, "\"error\" : \"Add key(%u) for controller table failed.\",", i);
        }
    }
}

/**
 * Tester
 *
 * This is the main function of this software, it is responsible to do the following tests:
 *
 *      1 - Open eBPF program
 *      2 - Load the oject without to attach it on targets
 *      3 - Count the number of eBPF programs
 *      4 - Attach the eBPF programs 
 *      5 - Unload the eBPF programs from target
 *      6 - Remove eBPF object
 *
 * @param filename   the name of the file to load.
 * @param names      vector with names to modify target.
 * @param maps       test internal data
 * @param ctrl       Fill ctrl table to have apps data (only available for netdata)
 *
 * @return It returns 'Success' or 'Fail' depending of final result.
 */
static char *ebpf_tester(char *filename, ebpf_specify_name_t *names, int maps, char *ctrl)
{
    static char *result[] = { "Success", "Fail" };

    struct bpf_object *obj =  bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        bpf_object__close(obj);
        return result[1];
    }
    
    if (bpf_object__load(obj)) {
        bpf_object__close(obj);
        return result[1];
    }

    size_t total =  ebpf_count_programs(obj);

    ebpf_attach_t load;
    int errors = ebpf_attach_programs(&load, obj, total, names);

    if (!errors && maps) {
        if (ctrl) {
            ebpf_fill_ctrl(obj, ctrl);
        }

        ebpf_test_maps(obj, ctrl);
    }

    if (!errors) {
        struct bpf_link **links = load.links;
        struct bpf_program *prog;
        size_t i = 0 ;
        bpf_object__for_each_program(prog, obj) {
            bpf_link__destroy(links[i]);
            i++;
        }
    }

    bpf_object__close(obj);

    return (load.success == total) ? result[0] : result[1];
}

/**
 *  Run netdata tests
 *
 *  Run tests for each eBPF program delivered by Netdata.
 *
 *  @param rhf_version   Is this a Red Hat family
 *  @param kver          The kernel version
 *  @param is_return     Load return or entry eBPF program
 *  @param flags         tests that software will run
 */
static void ebpf_run_netdata_tests(int rhf_version, uint32_t kver, int is_return, uint64_t flags)
{
    char load[FILENAME_MAX];
    int i = 0;
    while (ebpf_modules[i].name) {
        if (flags & ebpf_modules[i].flags) {
            uint32_t idx = ebpf_select_index(ebpf_modules[i].kernels, rhf_version, kver);
            ebpf_mount_name(load, FILENAME_MAX - 1, idx, ebpf_modules[i].name, is_return, rhf_version);

            ebpf_start_netdata_json(load, is_return);
            char *result = ebpf_tester(load, ebpf_modules[i].update_names, flags & NETDATA_FLAG_CONTENT, 
                                       ebpf_modules[i].ctrl_table);
            fprintf(stdlog, "    },\n    \"Status\" :  \"%s\"\n},\n", result);
        }

        i++;
    }
} 

/**
 * Memlock limit
 *
 * Adjust memory lock to avoid errors.
 *
 * @return It returns 0 on success and -1 otherwise.
 */
static int ebpf_memlock_limit()
{
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        return -1;
    }

    return 0;
}

/**
 * Help
 *
 * Write help on stdout.
 */
static void ebpf_help()
{
    fprintf(stdout, "Usage: ./legacy_test [OPTION]....\n"
                    "Load eBPF binaries printing final status of the test.\n\n" 
                    "The following global options are available:\n"
                    "--help             Prints this help.\n"
                    "--all              Test all netdata eBPF programs.\n"
                    "--common           Test eBPF programs that does not need specific module to be loaded.\n"
                    "                   This option does not test mdflush, ext4, nfs, zfs, xfs and btrfs.\n"
                    "--load-binary      Load a given eBPF program into  kernel.\n"
                    "--netdata-path     Directory where eBPF programs are present.\n"
                    "--log-path         Filename to write log information. When this option is not given,\n"
                    "                   software will use stderr.\n\n"
                    "--content          Test content stored inside hash tables.\n"
                    "--iteration        Number of iterations when content is read, default value is 1.\n"
                    "--pid              Specify the number that identifies PID  that will be monitored: 0 - Real Parent PID (Default), 1 - Parent PID, and 2 - All PID \n\n"
                    "You can also specify an unique eBPF program developed by Netdata with the following\n"
                    "options:\n"
                    "--btrfs            Latency for btrfs.\n"
                    "--cachestat        Linux page cache.\n"
                    "--dc               Linux directory cache.\n"
                    "--disk             Disk latency using tracepoints.\n"
                    "--ext4             Latency for ext4.\n"
                    "--filedescriptor   File descriptor actions(open and close).\n"
                    "--sync             Calls for sync (2) syscall.\n"
                    "--hardirq          Latency for hard IRQ.\n"
                    "--mdflush          Calls for md_flush_request.\n"
                    "--mount            Calls for mount (2) and umount (2) syscalls.\n"
                    "--oomkill          Monitoring oomkill events.\n"
                    "--process          Monitoring process life(Threads, start, exit).\n"
                    "--shm              Calls for syscalls shmget(2), shmat (2), shmdt (2), and shmctl (2).\n"
                    "--socket           Monitoring for TCP and UDP traffic.\n"
                    "--softirq          Latency for soft IRQ.\n"
                    "--swap             Monitor the exact time that processes try to execute IO events in swap.\n"
                    "--vfs              Monitor Virtual Filesystem functions.\n"
                    "--nfs              Latency for Network Filesystem NFS.\n"
                    "--xfs              Latency for XFS.\n"
                    "--zfs              Latency for ZFS.\n\n"
                    "Exit status:\n"
                    "0  if OK.\n"
                    "1  if kernel version cannot load eBPF programs.\n"
                    "2  if software cannot adjust memory\n"
           );
}

/**
 * Set common flag
 *
 * Set common flag to run tests.
 */
static uint64_t ebpf_set_common_flag()
{
    return NETDATA_FLAG_ALL &
                             ~(NETDATA_FLAG_FS | NETDATA_FLAG_LOAD_BINARY | NETDATA_FLAG_MDFLUSH | NETDATA_FLAG_CONTENT);
}

/**
 * Parse arguments
 *
 * Parse arguments given from command line.
 *
 * @param argc is the number of arguments
 * @param argv vector with values.
 * @param kver is the current kernel version
 *
 * @return It returns the flags used during the simulation.
 */
uint64_t ebpf_parse_arguments(int argc, char **argv, int kver)
{
    uint64_t flags = 0;
    int option_index = 0;
    static struct option long_options[] = {
        // specific tools
        {"btrfs",              no_argument,          0,  0 },
        {"cachestat",          no_argument,          0,  0 },
        {"dc",                 no_argument,          0,  0 },
        {"disk",               no_argument,          0,  0 },
        {"ext4",               no_argument,          0,  0 },
        {"filedescriptor",     no_argument,          0,  0 },
        {"sync",               no_argument,          0,  0 },
        {"hardirq",            no_argument,          0,  0 },
        {"mdflush",            no_argument,          0,  0 },
        {"mount",              no_argument,          0,  0 },
        {"oomkill",            no_argument,          0,  0 },
        {"process",            no_argument,          0,  0 },
        {"shm",                no_argument,          0,  0 },
        {"socket",             no_argument,          0,  0 },
        {"softirq",            no_argument,          0,  0 },
        {"swap",               no_argument,          0,  0 },
        {"vfs",                no_argument,          0,  0 },
        {"nfs",                no_argument,          0,  0 },
        {"xfs",                no_argument,          0,  0 },
        {"zfs",                no_argument,          0,  0 },

        // common options
        {"help",               no_argument,          0,  0 },
        {"all",                no_argument,          0,  0 },
        {"common",             no_argument,          0,  0 },
        {"load-binary",        required_argument,    0,  0 },
        {"netdata-path",       required_argument,    0,  0 },
        {"log-path",           required_argument,    0,  0 },
        {"content",            no_argument,          0,  0 },
        {"iteration",          required_argument,    0,  0 },
        {"pid",                required_argument,    0,  0 },

        // this must be always the last option
        {0,                no_argument, 0, 0}
    };

    while (1) {
        int c = getopt_long_only(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (option_index) {
            // SPECIFIC THREADS
            case NETDATA_OPT_BTRFS:
                {
                    flags |= NETDATA_FLAG_BTRFS;
                    break;
                }
            case NETDATA_OPT_CACHESTAT:
                {
                    flags |= NETDATA_FLAG_CACHESTAT;
                    break;
                }
            case NETDATA_OPT_DC:
                {
                    flags |= NETDATA_FLAG_DC;
                    break;
                }
            case NETDATA_OPT_DISK:
                {
                    flags |= NETDATA_FLAG_DISK;
                    break;
                }
            case NETDATA_OPT_EXT4:
                {
                    flags |= NETDATA_FLAG_EXT4;
                    break;
                }
            case NETDATA_OPT_FD:
                {
                    flags |= NETDATA_FLAG_FD;
                    break;
                }
            case NETDATA_OPT_SYNC:
                {
                    flags |= NETDATA_FLAG_SYNC;
                    break;
                }
            case NETDATA_OPT_HARDIRQ:
                {
                    flags |= NETDATA_FLAG_HARDIRQ;
                    break;
                }
            case NETDATA_OPT_MDFLUSH:
                {
                    flags |= NETDATA_FLAG_MDFLUSH;
                    break;
                }
            case NETDATA_OPT_MOUNT:
                {
                    flags |= NETDATA_FLAG_MOUNT;
                    break;
                }
            case NETDATA_OPT_OOMKILL:
                {
                    flags |= NETDATA_FLAG_OOMKILL;
                    break;
                }
            case NETDATA_OPT_PROCESS:
                {
                    flags |= NETDATA_FLAG_PROCESS;
                    break;
                }
            case NETDATA_OPT_SHM:
                {
                    flags |= NETDATA_FLAG_SHM;
                    break;
                }
            case NETDATA_OPT_SOCKET:
                {
                    flags |= NETDATA_FLAG_SOCKET;
                    break;
                }
            case NETDATA_OPT_SOFTIRQ:
                {
                    flags |= NETDATA_FLAG_SOFTIRQ;
                    break;
                }
            case NETDATA_OPT_SWAP:
                {
                    flags |= NETDATA_FLAG_SWAP;
                    break;
                }
            case NETDATA_OPT_VFS:
                {
                    flags |= NETDATA_FLAG_VFS;
                    break;
                }
            case NETDATA_OPT_NFS:
                {
                    flags |= NETDATA_FLAG_NFS;
                    break;
                }
            case NETDATA_OPT_XFS:
                {
                    flags |= NETDATA_FLAG_XFS;
                    break;
                }
            case NETDATA_OPT_ZFS:
                {
                    flags |= NETDATA_FLAG_ZFS;
                    break;
                }
            // COMMON OPTIONS    
            case NETDATA_OPT_HELP:
                {
                    ebpf_help();
                    exit(0);
                }
            case NETDATA_OPT_ALL:
                {
                    flags |= NETDATA_FLAG_ALL;
                    break;
                }
            case NETDATA_OPT_COMMON:
                {
                    flags |= ebpf_set_common_flag();
                    break;
                }
            case NETDATA_OPT_LOAD_BINARY:
                {
                    specific_ebpf = optarg;
                    flags |= NETDATA_FLAG_LOAD_BINARY;
                    break;
                }
            case NETDATA_OPT_CONTENT:
                {
                    flags |= NETDATA_FLAG_CONTENT;
                    break;
                }
            case NETDATA_OPT_NETDATA_PATH:
                {
                    netdata_path = optarg;
                    break;
                }
            case NETDATA_OPT_LOG_PATH:
                {
                    log_path = optarg;
                    stdlog = fopen(log_path, "a+");
                    if (!stdlog) {
                        stdlog = stderr;
                        fprintf(stdlog, "\"Error\": \"Cannot open %s\",\n", log_path);
                    }

                    break;
                }
            case NETDATA_OPT_ITERATION:
                {
                    int value = (int)strtol(optarg, NULL, 10);
                    if (value < 1) {
                        fprintf(stdlog, "\"Error\" : \"Value given (%d) is smaller than the minimum, resetting to default 1.\",\n",
                                value);
                        value = 1;
                    }

                    end_iteration = value;
                    break;
                }
            case NETDATA_OPT_PID:
                {
                    int value = (int)strtol(optarg, NULL, 10);
                    if (value < NETDATA_APPS_LEVEL_REAL_PARENT || value > NETDATA_APPS_LEVEL_ALL) {
                        fprintf(stdlog, "\"Error\" : \"Value given (%d) is not valid, resetting to default 0 (Real Parent).\",\n",
                                value);
                        value = NETDATA_APPS_LEVEL_REAL_PARENT;
                    }

                    map_level = value;
                    break;
                }
        }
    }

    // When user does not specify any flag, we will use common value
    if (!(flags & (NETDATA_FLAG_ALL & ~(NETDATA_FLAG_CONTENT))))
        flags |= ebpf_set_common_flag();

    // The necessary tracepoint was made in kernel 4.14, so we cannot
    // test before this version
    if (kver < NETDATA_EBPF_KERNEL_4_14)
        flags &= ~NETDATA_FLAG_OOMKILL;

    return flags;
}

/**
 * Fill names
 *
 * Update names used on different distributions
 */
static void ebpf_fill_names()
{
    ebpf_update_names(dc_optional_name);
}

/**
 * Clean names
 *
 * Clean names used to attach eBPF traces.
 */
static void ebpf_clean_name_vectors()
{
    ebpf_clean_optional(dc_optional_name);
}

/**
 * Write error exit
 *
 * Write an error in stdlog, close stdlog and exit with ret.
 *
 * @param msg is the error message.
 * @param ret is the return value.
 *
 * @return It returns the same value given for ret.
 */
static int ebpf_write_error_exit(char *msg, int ret)
{
    fprintf(stdlog, "\"Error\" : \"%s\",\n", msg);
    if (log_path)
        fclose(stdlog);

    return ret;
}

/**
 * Main
 *
 * Software entry point
 *
 * @param argc is the number of arguments
 * @param argv vector with values.
 *
 * @returt It returns 0 on success and another number otherwise.
 */
int main(int argc, char **argv)
{
    int my_kernel = ebpf_get_kernel_version();
    int rhf_version = ebpf_get_redhat_release();
    stdlog = stderr;
    nprocesses = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocesses < 0) {
        fprintf(stderr, "Cannot find number of proccess, using the default %lu\n", (unsigned long int)NETDATA_DEFAULT_PROCESS_NUMBER);
        nprocesses = NETDATA_DEFAULT_PROCESS_NUMBER;
    }

    uint64_t flags = ebpf_parse_arguments(argc, argv, my_kernel);

    // Start JSON output
    fprintf(stdlog, "{");

    if (ebpf_memlock_limit()) {
        return ebpf_write_error_exit("Cannot adjust memory limit.", 2);
    }

    if (!(flags & NETDATA_FLAG_LOAD_BINARY)) {
        ebpf_fill_names();

        ebpf_run_netdata_tests(rhf_version, my_kernel, 1, flags);
        ebpf_run_netdata_tests(rhf_version, my_kernel, 0, flags);

        ebpf_clean_name_vectors();
    } else {
        if (specific_ebpf) {
            ebpf_start_external_json(specific_ebpf);
            char *result = ebpf_tester(specific_ebpf, NULL, flags & NETDATA_FLAG_CONTENT, NULL);
            fprintf(stdlog, "    },\n    \"Status\" :  \"%s\"\n},\n", result);
        }
    }

    // END JSON output
    fprintf(stdlog, "\"End\" : \"Good bye!!!\" }\n");

    if (log_path)
        fclose(stdlog);

    return 0;
}

