#ifndef _NP_ARRAY_H_
#define _NP_ARRAY_H_

typedef struct NP_Array *NP_Array;

extern NP_Array NP_Array_new(size_t elem_size);
extern int      NP_Array_push(NP_Array array, void *data);
extern void    *NP_Array_get(NP_Array array, int index);
extern void     NP_Array_free(NP_Array array, void (*free_elem)(void *));

#endif /* _NP_ARRAY_H_ */
