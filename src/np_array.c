#include <stdlib.h>
#include <stdio.h>

#include "np_array.h"

struct NP_Array
{
	void **elem;
	size_t length;
};

NP_Array NP_Array_new()
{
	NP_Array array = malloc(sizeof(struct NP_Array));
	array->elem = NULL;
	array->length = 0;
	return array;
}

void NP_Array_free(NP_Array array, void (*free_elem)(void *))
{
	for (int i = 0; i < array->length; ++i)
		free_elem(array->elem[i]);
	free(array);
}

int NP_Array_push(NP_Array array, void *data)
{
	array->elem = realloc(array->elem, sizeof(void *) * (array->length + 1));
	array->elem[array->length] = data;
	return array->length++;
}

void *NP_Array_get(NP_Array array, int index)
{
	return array->elem[index];
}

