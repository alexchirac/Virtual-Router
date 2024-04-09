#include "lib.h"

#ifndef TREE_H
#define TREE_H


struct tree_node;

struct tree_node *create_new_node();

void insert_node(struct tree_node *root, struct route_table_entry *entry);

void insert_rtable(struct tree_node *root, struct route_table_entry *rtable, int len);

struct route_table_entry *get_best_route_tree(struct tree_node *root, uint32_t ip);


#endif
