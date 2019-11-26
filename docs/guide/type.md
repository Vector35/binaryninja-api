# Types and Structures

The types view can be opened from the top menu `View > Types`. From here you can create structures, unions, and types using C-style syntax.

## Shortcuts and Attributes

The creation shortcuts in this view are as follows.

* `S` - Create new structure
* `I` - Create new type
* `Shift+S` - Creating a new union

The shortcuts for editing are as follows. 

* `Y` - Edit type / field 
* `N` - Rename type / field
* `L` - Set structure size
* `U` - undefine field.

Structs support the attribute `__packed` to indicate that there is no padding.

## Examples 

```C
enum _flags
{
    F_X = 0x1,
    F_W = 0x2,
    F_R = 0x4
};
```

```C
struct Header __packed
{
    char *name;
    uint32_t version;
    void (* callback)();
    uint16_t size;
    enum _flags flags;
};
```
