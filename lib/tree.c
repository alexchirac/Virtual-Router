#include "tree.h"
#include "lib.h"
#include <arpa/inet.h>

struct tree_node
{
    struct tree_node *zero, *one;
    struct route_table_entry *entry;
};

struct tree_node *create_new_node()
{
    struct tree_node *new_node = (struct tree_node *)malloc(sizeof(struct tree_node));
    new_node->one = NULL;
    new_node->zero = NULL;
    new_node->entry = NULL;

    return new_node;
}

void insert_node(struct tree_node *root, struct route_table_entry *entry)
{
    struct tree_node *current = root;
    uint32_t iter = 1 << 31;
    uint32_t mask = ntohl(entry->mask);
    uint32_t prefix = ntohl(entry->prefix);
    while (iter & mask) {
        if (iter & prefix) {
            if (current->one == NULL) {
                current->one = create_new_node();
            }
            current = current->one;
        } else {
            if (current->zero == NULL) {
                current->zero = create_new_node();
            }
            current = current->zero;
        }
        iter = iter >> 1;
    }
    current->entry = entry;
}

struct route_table_entry *get_best_route_tree(struct tree_node *root, uint32_t ip)
{
    struct tree_node *current = root;
    uint32_t iter = 1 << 31;
    struct route_table_entry *best_route = NULL;
    for (int i = 0; i < 32; i++) {
        if (current->entry)
            best_route = current->entry;
        if (iter & ip) {
            if (current->one == NULL)
                break;
            current = current->one;
        } else {
            if (current->zero == NULL)
                break;
            current = current->zero;
        }
        iter = iter >> 1;
    }
    if (current->entry)
        best_route = current->entry;
    
    return best_route;
}

void insert_rtable(struct tree_node *root, struct route_table_entry *rtable, int len)
{
    for (int i = 0; i < len; i++) {
        insert_node(root, &rtable[i]);
    }
}