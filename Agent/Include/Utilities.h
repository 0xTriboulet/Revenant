//
// Created by 0xtriboulet on 3/30/2023.
//

#ifndef REVENANT_UTILITIES_H
#define REVENANT_UTILITIES_H

void *mem_set(void *dest, int value, size_t count);
void *mem_cpy(void *dest, const void *src, size_t count);

size_t str_len(const char* str);

char* str_dup(const char* str);
char* mem_cat(const void* ptr1, size_t size1, const void* ptr2, size_t size2);
char** split_first_space(const char* str);
size_t sizeof_w(const wchar_t* str);
wchar_t* wide_concat(const wchar_t* str1, const wchar_t* str2);

#if CONFIG_NATIVE
void normalize_path(char* path);
#endif



#endif //REVENANT_UTILITIES_H
