@@
identifier func =~ ".*_create$";
identifier event, dnode, resource;
@@

int
- func(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
+ func(int NB_CB_CREATE_ARGS)
  { ... }

@@
identifier func =~ ".*_modify$";
identifier event, dnode, resource;
@@

int
- func(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
+ func(int NB_CB_MODIFY_ARGS)
  { ... }

@@
identifier func =~ ".*_destroy$";
identifier event, dnode;
@@

int
- func(enum nb_event event, const struct lyd_node *dnode)
+ func(int NB_CB_DESTROY_ARGS)
  { ... }

@@
identifier func =~ ".*_pre_validate$";
identifier dnode;
@@

int
- func(const struct lyd_node dnode)
+ func(int NB_CB_PRE_VALIDATE_ARGS)
  { ... }

@@
identifier func =~ ".*_apply_finish$";
identifier dnode;
@@

void
- func(const struct lyd_node *dnode)
+ func(int NB_CB_APPLY_FINISH_ARGS)
  { ... }

@@
identifier func =~ ".*_get_elem$";
identifier xpath, list_entry;
@@

struct yang_data *
- func(const char *xpath, const void *list_entry)
+ func(int NB_CB_GET_ELEM_ARGS)
  { ... }

@@
identifier func =~ ".*_get_next$";
identifier parent_list_entry, list_entry;
@@

const void *
- func(const void *parent_list_entry, const void *list_entry)
+ func(int NB_CB_GET_NEXT_ARGS)
  { ... }

@@
identifier func =~ ".*_get_keys$";
identifier list_entry, keys;
@@

int
- func(const void *list_entry, struct yang_list_keys *keys)
+ func(int NB_CB_GET_KEYS_ARGS)
  { ... }

@@
identifier func =~ ".*_lookup_entry$";
identifier parent_list_entry, keys;
@@

const void *
- func(const void *parent_list_entry, const struct yang_list_keys *keys)
+ func(int NB_CB_LOOKUP_ENTRY_ARGS)
  { ... }

@@
identifier func =~ ".*_rpc$";
identifier xpath, input, output;
@@

int
- func(const char *xpath, const struct list *input, struct list *output)
+ func(int NB_CB_RPC_ARGS)
  { ... }

@@
identifier func =~ ".*_create$";
identifier event, dnode, resource;
@@

int
- func(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
+ func(int NB_CB_CREATE_ARGS)
;

@@
identifier func =~ ".*_modify$";
identifier event, dnode, resource;
@@

int
- func(enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource)
+ func(int NB_CB_MODIFY_ARGS)
;

@@
identifier func =~ ".*_destroy$";
identifier event, dnode;
@@

int
- func(enum nb_event event, const struct lyd_node *dnode)
+ func(int NB_CB_DESTROY_ARGS)
;

@@
identifier func =~ ".*_pre_validate$";
identifier dnode;
@@

int
- func(const struct lyd_node dnode)
+ func(int NB_CB_PRE_VALIDATE_ARGS)
;

@@
identifier func =~ ".*_apply_finish$";
identifier dnode;
@@

void
- func(const struct lyd_node *dnode)
+ func(int NB_CB_APPLY_FINISH_ARGS)
;

@@
identifier func =~ ".*_get_elem$";
identifier xpath, list_entry;
@@

struct yang_data *
- func(const char *xpath, const void *list_entry)
+ func(int NB_CB_GET_ELEM_ARGS)
;

@@
identifier func =~ ".*_get_next$";
identifier parent_list_entry, list_entry;
@@

const void *
- func(const void *parent_list_entry, const void *list_entry)
+ func(int NB_CB_GET_NEXT_ARGS)
;

@@
identifier func =~ ".*_get_keys$";
identifier list_entry, keys;
@@

int
- func(const void *list_entry, struct yang_list_keys *keys)
+ func(int NB_CB_GET_KEYS_ARGS)
;

@@
identifier func =~ ".*_lookup_entry$";
identifier parent_list_entry, keys;
@@

const void *
- func(const void *parent_list_entry, const struct yang_list_keys *keys)
+ func(int NB_CB_LOOKUP_ENTRY_ARGS)
;

@@
identifier func =~ ".*_rpc$";
identifier xpath, input, output;
@@

int
- func(const char *xpath, const struct list *input, struct list *output)
+ func(int NB_CB_RPC_ARGS)
;
