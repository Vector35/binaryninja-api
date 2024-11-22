# MSVC RTTI

Parses and symbolizes MSVC RTTI information in [Binary Ninja].

## Example Complete Object Locator

This analysis can be triggered with the `MSVC\\Find RTTI` command.

```cpp
struct _RTTICompleteObjectLocator MapTrackView::`RTTI Complete Object Locator'{for `QPaintDevice'} = 
{
    enum signature = COL_SIG_REV1
    uint32_t offset = 0x10
    uint32_t cdOffset = 0x0
    void* __based(start) pTypeDescriptor = class MapTrackView `RTTI Type Descriptor' {__dos_header + 0x2071e8}
    struct _RTTIClassHierarchyDescriptor* __based(start) pClassHierarchyDescriptor = MapTrackView::`RTTI Class Hierarchy Descriptor' {__dos_header + 0x1c6128}
    void* __based(start) pSelf = MapTrackView::`RTTI Complete Object Locator'{for `QPaintDevice'} {__dos_header + 0x1c61a0}
}
```

_The above listing includes type information deduced separately through demangled names_

## Example Virtual Function Table Listing

This analysis can be triggered with the `MSVC\\Find VFTs` command.

```cpp
void* data_14013bfd8 = MapTrackView::`RTTI Complete Object Locator'{for `QPaintDevice'}
struct QPaintDevice::MapTrackView::VTable MapTrackView::`vftable'{for `QPaintDevice'} = 
{
    int64_t (* const vFunc_0)(int64_t arg1, char arg2, int512_t arg3) = sub_140053114
    int32_t (* const vFunc_1)(QWidget* this) = Qt5Widgets:QWidget::devType(QWidget* this) const__ptr64
    class QPaintEngine* __ptr64 (* const vFunc_2)(QWidget* this) = Qt5Widgets:QWidget::paintEngine(QWidget* this) const__ptr64
    int32_t (* const vFunc_3)(QWidget* this, enum QPaintDevice::PaintDeviceMetric arg2) = Qt5Widgets:QWidget::metric(QWidget* this, enum QPaintDevice::PaintDeviceMetric) const__ptr64
    void (* const vFunc_4)(QWidget* this, class QPainter* __ptr64 arg2) = Qt5Widgets:QWidget::initPainter(QWidget* this, class QPainter* __ptr64) const__ptr64
    class QPaintDevice* __ptr64 (* const vFunc_5)(QWidget* this, class QPoint* __ptr64 arg2) = Qt5Widgets:QWidget::redirected(QWidget* this, class QPoint* __ptr64) const__ptr64
    class QPainter* __ptr64 (* const vFunc_6)(QWidget* this) = Qt5Widgets:QWidget::sharedPainter(QWidget* this) const__ptr64
}
```

_The above listing includes type information deduced separately through demangled names_

## Exposed Metadata

This plugin will store metadata on the view queryable view the `msvc` key.

### Example Metadata

```py
# data = bv.query_metadata("msvc")
data = {
    "classes": {
        "5368823328": {
            "className": "Animal",
            "vft": {
                "address": 5368818736,
                "functions": [{"address": 5368779647}, {"address": 5368779152}],
            },
        },
        "5368823464": {
            "className": "Flying",
            "vft": {"address": 5368818768, "functions": [{"address": 5368778982}]},
        },
        "5368823600": {
            "baseClassName": "Animal",
            "className": "Bird",
            "vft": {
                "address": 5368818816,
                "functions": [{"address": 5368779137}, {"address": 5368779272}],
            },
        },
        "5368823808": {
            "baseClassName": "Flying",
            "className": "Bird",
            "classOffset": 16,
            "vft": {"address": 5368818848, "functions": [{"address": 5368778982}]},
        },
        "5368823856": {
            "className": "type_info",
            "vft": {"address": 5368818888, "functions": [{"address": 5368778927}]},
        },
    }
}
```

[Binary Ninja]: https://binary.ninja