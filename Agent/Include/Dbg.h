//
// Created by 0xtriboulet on 5/14/2023.
//
// From Lear C the Hard Way: https://github.com/zedshaw/learn-c-the-hard-way-lectures/blob/master/dbg.h
#ifndef REVENANT_DBG_H
#define REVENANT_DBG_H

#ifndef __dbg_h__
#define __dbg_h__

#ifdef NDEBUG
#define debug(M, ...)
#else

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n",\
        __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define clean_errno() (errno == 0 ? "None" : strerror(errno))

#define log_err(M, ...) fprintf(stderr,\
        "[ERROR] (%s:%d: errno: %s) " M "\n", __FILE__, __LINE__,\
        clean_errno(), ##__VA_ARGS__)

#define log_warn(M, ...) fprintf(stderr,\
        "[WARN] (%s:%d: errno: %s) " M "\n",\
        __FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

#define log_info(M, ...) fprintf(stderr, "[INFO] (%s:%d) " M "\n",\
        __FILE__, __LINE__, ##__VA_ARGS__)

#define check(A, M, ...) if(!(A)) {\
    log_err(M, ##__VA_ARGS__); errno=0; goto LEAVE; }

#define sentinel(M, ...)  { log_err(M, ##__VA_ARGS__);\
    errno=0; goto LEAVE; }

#define check_mem(A) check((A), "Out of memory.")

#define check_debug(A, M, ...) if(!(A)) { debug(M, ##__VA_ARGS__);\
    errno=0; goto LEAVE; }

#endif

#endif //REVENANT_DBG_H
