# Working with Types, Structures, and Symbols

This document is organized into four sections describing how to work with types in Binary Ninja. The first [section](#working-with-types) is how to interact with any type, regardless of its source.

The [second section](#type-library) explains how to work with the Type Library. This includes multiple sources of information from which Binary Ninja can automatically source for type information from and how you can add to them.

Next, the [third section](#signature-library) explains how to work with the signature library. While the signature library technically does not directly inform types, it will help automatically match statically compiled functions which are then matched with the type libraries described in the previous section.

Finally, we'll [cover](#symbols) how to work with Symbols in a binary.

# Working With Types

There are two main ways to interact with types from within a binary view. The first is to use the [types view](#types-view), and the second is to take advantage of the [smart structures workflow](#smart-structures-workflow) or otherwise annotate types directly in a disassembly or IL view.

## Smart Structures Workflow

New to [stable version 1.3.2015](https://binary.ninja/changelog/) is the "Smart Structures" feature. Rather than manually create a type in the type view and then apply it to disassembly, you can create structures directly from disassembly using the `s` hotkey.  Consider the following example (created using [taped](http://captf.com/2011/gits/taped) from the 2011 Ghost in the Shellcode CTF if you'd like to play along at home):

<div class="inline-slides">
    <ol id="inline-slides-text">
        <li id="currentline">Assembly view of the start of <code>0x8048e20</code></li>
        <li>MLIL view of the same basic block</li>
        <li>MLIL view after selecting the return of <code>calloc</code> and pressing <code>s</code></li>
        <li>MLIL view after selecting the offset and pressing <code>s</code> to turn it into a member access</li>
        <li>MLIL view after selecting the remaining offsets and pressing <code>s</code> in turn</li>
        <li>Viewing the structure automatically created after this workflow</li>
        <li>Selecting the remaining bytes and turning them into an array using <code>1</code> to turn them all into uint_8 variables, and then <code>*</code> to turn them all into an array</li>
    </ol>
    <div id="image-slider-container">
        <ul id="image-slider">
            <li>
              <img src="../img/taped-1.png" alt="Structure Workflow 1"/>
            </li>
            <li>
              <img src="../img/taped-2.png" alt="Structure Workflow 2"/>
            </li>
            <li>
              <img src="../img/taped-3.png" alt="Structure Workflow 3"/>
            </li>
            <li>
              <img src="../img/taped-4.png" alt="Structure Workflow 4"/>
            </li>
            <li>
              <img src="../img/taped-5.png" alt="Structure Workflow 5"/>
            </li>
            <li>
              <img src="../img/taped-6.png" alt="Structure Workflow 6"/>
            </li>
            <li>
              <img src="../img/taped-7.png" alt="Structure Workflow 7"/>
            </li>
        </ul>
    </div>
</div>

_hover over the image to temporarily pause_


<script>
document.addEventListener("DOMContentLoaded", function(event) {
    let pause = 3000;
    let slider = $("#image-slider");
    let sliderContainer = $(slider.selector + "-container");
    window.slider = slider.lightSlider({
        item:1,
        loop: false,
        auto: true,
        speed: 200,
        pause: pause,
        slideMargin: 0,
        pauseOnHover: true,
        autoWidth:false,
        thumbMargin:0,
        onBeforeSlide: function (el) {
            Array.from($('ol#inline-slides-text')[0].children).forEach(function(item, index, arr) {
              if (index == el.getCurrentSlideCount() - 1)
                item.id = "currentline";
              else
                item.id = "";
             });
        },
        onSliderLoad: function() {
            let sliderHeight = slider.height();
            slider.find('img').each(function() {
                $(this).parent().css("padding-top", (sliderHeight - this.naturalHeight)/2);
            });
            slider.removeClass('hiddenc');
        },
        onAfterSlide: function(el) {
            if (el.getCurrentSlideCount() == el.getTotalSlideCount()) {
                setTimeout(() => {!el.is(':hover') && el.goToSlide(0)}, pause);
            }
        },
        onBeforeStart: function() {
            let width = 0;
            slider.find('img').each(function() {
                width = Math.max(width, this.naturalWidth);
            });
            sliderContainer.width(width);
        },
    });
    Array.from($('ol#inline-slides-text')[0].children).forEach(function(item, index, arr) {
        item.addEventListener('click', function() { window.slider.goToSlide(index)});
    });
});
</script>

Note that the last step is entirely optional. Now that we've created a basic structure, and if we happen to do a bit of reverse engineering we learn that this is actually a linked list and that the structure should look like:

```C
struct Page
{
    int num;
    int count;
    Tape* tapes[8];
    struct Page* prev;
    struct Page* next;
}
```

Where tapes is:
```C
struct Tape
{
    int id;
    char* name;
    char text[256];
};
```

We can either update our automatically created structure by pressing `y` to change member types and `n` to change their names, or we can use the [types view](#types-view) to directly import the c code directly and then apply the types using `y`. That gives us HLIL that now looks like:

![Taped HLIL](../img/taped-hlil.png "Taped HLIL")


## Types View

To see all types in a Binary View, use the types view. It can be accessed from the menu `View > Types`. Alternatively, you can access it with the `t` hotkey from most other views, or using `[CMD/CTRL] p` to access the command-palette and typing "types". This is the most common interface for creating structures, unions and types using C-style syntax.

For many built-in file formats you'll notice that common headers are already enumerated in the types view. These headers are applied when viewing the binary in [linear view](../getting-started.md#linear-view) and will show the parsed binary data into that structure or type making them particularly useful for binary parsing even of non-executable file formats.

![Types View](../img/types-view.png "Types View")

### Shortcuts and Attributes

From within the Types view, you can use the following hotkeys to create new types, structures, or unions. Alternatively, you can use the right-click menu to access these options and more.

![Types Right Click Menu >](../img/types-right-click-menu.png "Types Right Click Menu")

* `s` - Create new structure
* `i` - Create new type
* `[SHIFT] s` - Creating a new union

The shortcuts for editing existing elements are:

* `y` - Edit type / field 
* `n` - Rename type / field
* `l` - Set structure size
* `u` - undefine field

Structs support the attribute `__packed` to indicate that there is no padding. Additionally, function prototypes support the following keywords to indicate their calling convention:

```
__cdecl
__stdcall
__fastcall
__convention
__noreturn
```


### Applying Structures and Types

![Changing a type](../img/change-type.png "Changing a type")

Once you've created your structures, you can apply them to your disassembly. Simply select an appropriate token (variable or memory address), and press `y` to bring up the change type dialog. Note that for simple types you can also create them directly in the linear views or graph views. Additionally, you can apply types on both disassembly and all levels of IL. Any variables that are shared between the ILs will be updated through all of them as types are applied. 


### Examples 

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

# Using the API

Of course, like everything else in Binary Ninja, anything you can accomplish in the UI you can accomplish using the API. Manipulating types is no exception. Here are four common workflows for working with types as commented examples. 

## Create a new type

First we'll want to make a new type, then we'll want to insert it into a BinaryView and then finally we'll want to apply it to a location in memory.

### From C syntax

There are two main ways to create a type with the API. The first is to use [one of](https://api.binary.ninja/search.html?q=parse_type&check_keywords=yes&area=default#) our APIs that parse a type string and return a type object. For a simple, single type, [parse_type_string](https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.BinaryView.parse_type_string) will return a tuple of the [Type](https://api.binary.ninja/binaryninja.types.Type.html#binaryninja.types.Type) and the [QualifiedName](https://api.binary.ninja/binaryninja.types.QualifiedName.html#binaryninja.types.QualifiedName):

```py
>>> bv.parse_type_string("int foo")
(<type: int32_t>, 'foo')
>>>
```

For more complicated types that are already in C syntax, you may want to take advantage of the [parse_types_*](https://api.binary.ninja/search.html?q=parse_types&check_keywords=yes&area=default) APIs. 

```py
>>> bv.platform.parse_types_from_source('''
enum colors {blue, green, brown};

struct person
{
	char name[20];
	int age;
	colors eyecolor;
};
''')
<types: {'colors': <type: enum>, 'person': <type: struct>}, variables: {}, functions: {}>
```

If you're importing a large number of headers from an existing project you might find that some features are not compatible with the type parser that Binary Ninja uses. In that case, you may find the [Header Plugin](https://github.com/rmspeers/binja_load_headers) useful as it attempts to automate the normalization of these features in a way that simplifies importing headers into your analysis.

NOTE: While they have similar names, be aware that the parse_types APIs live off of the [Platform](https://api.binary.ninja/binaryninja.platform.Platform.html#binaryninja.platform.Platform) class as they require knowledge of the existing architecture's platform whereas the simpler `parse_type_string` is accessed directly from the [BinaryView](https://api.binary.ninja/binaryninja.binaryview.BinaryView.html#binaryninja.binaryview.BinaryView) class.

### Using Type objects

Base [types](https://api.binary.ninja/binaryninja.types-module.html) can be easily composed to create simple type objects:

```py
>>> myar = Type.array(Type.char(), 20)
>>> print(repr(myar))
<type: char [20]>
```

### Adding types

Next, we're going to take the optional step of inserting our type into the current BinaryView with the [define_user_type](https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.BinaryView.define_user_type) API:


```py
>>> bv.define_user_type("myString", myar)
```

And we can verify the type shows up in the types view as expected:

![Custom type](../img/mystring.png "Custom type")

This makes the type available to the user to apply more easily and is appropriate for named structures, but is not required if you simply with to set a type as shown in the next step.

### Applying 

Of course, having the type available doesn't actually apply it to anything in the Binary. Let's examine our [sample binary](http://captf.com/2011/gits/taped), find a suitable string like the one at `0x8049f34` and create a data variable using our new type:

```py
>>> bv.define_data_var(here, bv.types["myString"])
```
And now we can see that the string was indeed applied to our location:

![Custom type](../img/stringapplied.png "Custom type")

Of course, we could have just directly applied our type without inserting it into the types available in the binary. For example:

```py
>>> bv.define_data_var(here, Type.array(Type.char(), 20))
```

If we want to name the variable there, see the section below on working with [symbols](#symbols).


## Delete a type

_coming soon..._

## Change the name of a member of an existing struct

_coming soon..._

## Add/remove/change the type of a member of an existing struct

_coming soon..._



# Type Library

_coming soon..._

# Signature Library

While many signatures are [built-in](https://github.com/Vector35/binaryninja-api/issues/1551) and require no interaction to automatically match functions, you may wish to add or modify your own. First, install the [SigKit](https://github.com/Vector35/sigkit/) plugin from the [plugin manager](plugins.md#plugin-manager).

## Running the signature matcher

The signature matcher runs automatically by default once analysis completes. You can turn this off in `Settings > Analysis > Autorun Function Signature Matcher` (or, [analysis.signatureMatcher.autorun](../getting-started.md#analysis.signatureMatcher.autorun) in Settings).

You can also trigger the signature matcher to run from the menu `Tools > Run Analysis Module > Signature Matcher`.

Once the signature matcher runs, it will print a brief report to the console detailing how many functions it matched and will rename matched functions. For example:

```txt
1 functions matched total, 0 name-only matches, 0 thunks resolved, 33 functions skipped because they were too small
```

## Generating signature libraries

To generate a signature library for the currently-open binary, use `Tools > Signature Library > Generate Signature Library`. This will generate signatures for all functions in the binary that have a name attached to them. Note that functions with automatically-chosen names such as `sub_401000` will be skipped. Once it's generated, you'll be prompted where to save the resulting signature library.

For headless users, you can generate signature libraries by using the sigkit API ([examples](https://github.com/Vector35/sigkit/tree/master/examples) and [documentation](https://github.com/Vector35/sigkit/blob/master/__init__.py#L46)). For more detailed information, see our blog post describing [signature generation](https://binary.ninja/2020/03/11/signature-libraries.html#signature-generation).

If you are accessing the sigkit API through the Binary Ninja GUI and you've installed the sigkit plugin through the plugin manager, you will need to import sigkit under a different name:

```python
import Vector35_sigkit as sigkit
```

## Installing signature libraries

Binary Ninja loads signature libraries from 2 locations:

 - [$INSTALL_DIR](https://docs.binary.ninja/getting-started.html#binary-path)/signatures/$PLATFORM
 - [$USER_DIR](https://docs.binary.ninja/getting-started.html#user-folder)/signatures/$PLATFORM

**WARNING**: Always place your signature libraries in your user directory. The install path is wiped whenever Binary Ninja auto-updates. You can locate it with `Open Plugin Folder` in the command palette and navigate "up" a directory.

Inside the signatures folder, each platform has its own folder for its set of signatures. For example, `windows-x86_64` and `linux-ppc32` are two sample platforms. When the signature matcher runs, it uses the signature libraries that are relevant to the current binary's platform. (You can check the platform of any binary you have open in the UI using the console and typing `bv.platform`)

### Manipulating signature libraries

You can edit signature libraries programmatically using the sigkit API. A very basic [example](https://github.com/Vector35/sigkit/blob/master/examples/convert_siglib.py) shows how to load and save signature libraries. Note that Binary Ninja only supports signatures in the `.sig` format; the other formats are for debugging. The easiest way to load and save signature libraries in this format are the [`sigkit.load_signature_library()`](https://github.com/Vector35/sigkit/blob/master/__init__.py) and [`sigkit.save_signature_library()`](https://github.com/Vector35/sigkit/blob/master/__init__.py) functions.

To help debug and optimize your signature libraries in a Signature Explorer GUI by using `Tools > Signature Library > Explore Signature Library`. This GUI can be opened through the sigkit API using [`sigkit.signature_explorer()`](https://github.com/Vector35/sigkit/blob/master/__init__.py) and [`sigkit.explore_signature_library()`](https://github.com/Vector35/sigkit/blob/master/sigexplorer.py).

For a text-based approach, you can also export your signature libraries to JSON using the Signature Explorer. Then, you can edit them in a text editor and convert them back to a .sig using the Signature Explorer afterwards. Of course, these conversions are also accessible through the API as the [`sigkit.sig_serialize_json`](https://github.com/Vector35/sigkit/blob/master/sig_serialize_json.py) module, which provides a pickle-like interface. Likewise, [`sigkit.sig_serialize_fb`](https://github.com/Vector35/sigkit/blob/master/sig_serialize_fb.py) provides serialization for the standard .sig format.


# Symbols

Some binaries helpfully have symbol information in them which makes reverse engineering easier. Of course, even if the binary doesn't come with symbol information, you can always add your own. From the UI, this couldn't be simpler. Just select the function, variable, member, register, or whatever you want to change the symbol of and press `n`. 

![Rename a function >](../img/rename.png "Renaming a function")

That's it! From an API perspective, there are some helper functions to make the process easier. For example, to rename a function:

```py
>>> current_function.name
'main'
>>> current_function.name = "newName"
>>> current_function.name
'newName'
```

Other objects or variables may need a [symbol](https://api.binary.ninja/binaryninja.types.Symbol.html) created and applied:

```py
>>> mysym = Symbol(SymbolType.FunctionSymbol, here, "myVariableName")
>>> mysym
<SymbolType.FunctionSymbol: "myVariableName" @ 0x80498d0>
>>> bv.define_user_symbol(mysym)
```

Note that `here` and `bv` are used in many of the previous examples. These shortcuts and [several others](../getting-started.md#script-python-console) are only available when running in the Binary Ninja python console and are used here for convenience.

Valid symbol types [include](https://api.binary.ninja/binaryninja.enums.SymbolType.html):

| SymbolType | Description | 
| ---------- | ----------- |
	| FunctionSymbol |            Symbol for function that exists in the current binary |
	| ImportAddressSymbol |       Symbol defined in the Import Address Table |
	| ImportedFunctionSymbol |    Symbol for a function that is not defined in the current binary |
	| DataSymbol |                Symbol for data in the current binary |
	| ImportedDataSymbol |        Symbol for data that is not defined in the current binary |
	| ExternalSymbol |            Symbols for data and code that reside outside the BinaryView |
	| LibraryFunctionSymbol |     Symbols for external functions outside the library |
