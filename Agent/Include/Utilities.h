//
// Created by 0xtriboulet on 3/30/2023.
//

#ifndef REVENANT_UTILITIES_H
#define REVENANT_UTILITIES_H

void *mem_set(void *dest, int value, size_t count);
void *mem_cpy(void *dest, const void *src, size_t count);
void normalize_path(char* path);


#endif //REVENANT_UTILITIES_H
