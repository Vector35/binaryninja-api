// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/libxml/schemasInternals.h

enum macro_xml_schema_flags {
/**
 * XML_SCHEMAS_ANYATTR_SKIP:
 *
 * Skip unknown attribute from validation
 * Obsolete, not used anymore.
 */
/*line: 161*/   XML_SCHEMAS_ANYATTR_SKIP = 0x1,  // 1
/**
 * XML_SCHEMAS_ANYATTR_LAX:
 *
 * Ignore validation non definition on attributes
 * Obsolete, not used anymore.
 */
/*line: 168*/   XML_SCHEMAS_ANYATTR_LAX = 0x2,  // 2
/**
 * XML_SCHEMAS_ANYATTR_STRICT:
 *
 * Apply strict validation rules on attributes
 * Obsolete, not used anymore.
 */
/*line: 175*/   XML_SCHEMAS_ANYATTR_STRICT = 0x3,  // 3
/**
 * XML_SCHEMAS_ANY_SKIP:
 *
 * Skip unknown attribute from validation
 */
/*line: 181*/   XML_SCHEMAS_ANY_SKIP = 0x1,  // 1
/**
 * XML_SCHEMAS_ANY_LAX:
 *
 * Used by wildcards.
 * Validate if type found, don't worry if not found
 */
/*line: 188*/   XML_SCHEMAS_ANY_LAX = 0x2,  // 2
/**
 * XML_SCHEMAS_ANY_STRICT:
 *
 * Used by wildcards.
 * Apply strict validation rules
 */
/*line: 195*/   XML_SCHEMAS_ANY_STRICT = 0x3,  // 3
/**
 * XML_SCHEMAS_ATTR_USE_PROHIBITED:
 *
 * Used by wildcards.
 * The attribute is prohibited.
 */
/*line: 202*/   XML_SCHEMAS_ATTR_USE_PROHIBITED = 0x0,  // 0
/**
 * XML_SCHEMAS_ATTR_USE_REQUIRED:
 *
 * The attribute is required.
 */
/*line: 208*/   XML_SCHEMAS_ATTR_USE_REQUIRED = 0x1,  // 1
/**
 * XML_SCHEMAS_ATTR_USE_OPTIONAL:
 *
 * The attribute is optional.
 */
/*line: 214*/   XML_SCHEMAS_ATTR_USE_OPTIONAL = 0x2,  // 2
/**
 * XML_SCHEMAS_ATTR_GLOBAL:
 *
 * allow elements in no namespace
 */
/*line: 220*/   XML_SCHEMAS_ATTR_GLOBAL = 0x1,  // 1<<0
/**
 * XML_SCHEMAS_ATTR_NSDEFAULT:
 *
 * allow elements in no namespace
 */
/*line: 226*/   XML_SCHEMAS_ATTR_NSDEFAULT = 0x80,  // 1<<7
/**
 * XML_SCHEMAS_ATTR_INTERNAL_RESOLVED:
 *
 * this is set when the "type" and "ref" references
 * have been resolved.
 */
/*line: 233*/   XML_SCHEMAS_ATTR_INTERNAL_RESOLVED = 0x100,  // 1<<8
/**
 * XML_SCHEMAS_ATTR_FIXED:
 *
 * the attribute has a fixed value
 */
/*line: 239*/   XML_SCHEMAS_ATTR_FIXED = 0x200,  // 1<<9
};

enum macro_wildcard_complete {
/**
 * XML_SCHEMAS_WILDCARD_COMPLETE:
 *
 * If the wildcard is complete.
 */
/*line: 288*/   XML_SCHEMAS_WILDCARD_COMPLETE = 0x1,  // 1<<0
};

enum macro_attrgroup_flags {
/**
 * XML_SCHEMAS_ATTRGROUP_WILDCARD_BUILDED:
 *
 * The attribute wildcard has been built.
 */
/*line: 326*/   XML_SCHEMAS_ATTRGROUP_WILDCARD_BUILDED = 0x1,  // 1<<0
/**
 * XML_SCHEMAS_ATTRGROUP_GLOBAL:
 *
 * The attribute group has been defined.
 */
/*line: 332*/   XML_SCHEMAS_ATTRGROUP_GLOBAL = 0x2,  // 1<<1
/**
 * XML_SCHEMAS_ATTRGROUP_MARKED:
 *
 * Marks the attr group as marked; used for circular checks.
 */
/*line: 338*/   XML_SCHEMAS_ATTRGROUP_MARKED = 0x4,  // 1<<2
/**
 * XML_SCHEMAS_ATTRGROUP_REDEFINED:
 *
 * The attr group was redefined.
 */
/*line: 345*/   XML_SCHEMAS_ATTRGROUP_REDEFINED = 0x8,  // 1<<3
/**
 * XML_SCHEMAS_ATTRGROUP_HAS_REFS:
 *
 * Whether this attr. group contains attr. group references.
 */
/*line: 351*/   XML_SCHEMAS_ATTRGROUP_HAS_REFS = 0x10,  // 1<<4
};

enum macro_xml_schemas_types {
/**
 * XML_SCHEMAS_TYPE_MIXED:
 *
 * the element content type is mixed
 */
/*line: 408*/   XML_SCHEMAS_TYPE_MIXED = 0x1,  // 1<<0
/**
 * XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION:
 *
 * the simple or complex type has a derivation method of "extension".
 */
/*line: 414*/   XML_SCHEMAS_TYPE_DERIVATION_METHOD_EXTENSION = 0x2,  // 1<<1
/**
 * XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION:
 *
 * the simple or complex type has a derivation method of "restriction".
 */
/*line: 420*/   XML_SCHEMAS_TYPE_DERIVATION_METHOD_RESTRICTION = 0x4,  // 1<<2
/**
 * XML_SCHEMAS_TYPE_GLOBAL:
 *
 * the type is global
 */
/*line: 426*/   XML_SCHEMAS_TYPE_GLOBAL = 0x8,  // 1<<3
/**
 * XML_SCHEMAS_TYPE_OWNED_ATTR_WILDCARD:
 *
 * the complexType owns an attribute wildcard, i.e.
 * it can be freed by the complexType
 */
/*line: 433*/   XML_SCHEMAS_TYPE_OWNED_ATTR_WILDCARD = 0x10, /* Obsolete. */ // 1<<4
/**
 * XML_SCHEMAS_TYPE_VARIETY_ABSENT:
 *
 * the simpleType has a variety of "absent".
 * TODO: Actually not necessary :-/, since if
 * none of the variety flags occur then it's
 * automatically absent.
 */
/*line: 442*/   XML_SCHEMAS_TYPE_VARIETY_ABSENT = 0x20,  // 1<<5
/**
 * XML_SCHEMAS_TYPE_VARIETY_LIST:
 *
 * the simpleType has a variety of "list".
 */
/*line: 448*/   XML_SCHEMAS_TYPE_VARIETY_LIST = 0x40,  // 1<<6
/**
 * XML_SCHEMAS_TYPE_VARIETY_UNION:
 *
 * the simpleType has a variety of "union".
 */
/*line: 454*/   XML_SCHEMAS_TYPE_VARIETY_UNION = 0x80,  // 1<<7
/**
 * XML_SCHEMAS_TYPE_VARIETY_ATOMIC:
 *
 * the simpleType has a variety of "union".
 */
/*line: 460*/   XML_SCHEMAS_TYPE_VARIETY_ATOMIC = 0x100,  // 1<<8
/**
 * XML_SCHEMAS_TYPE_FINAL_EXTENSION:
 *
 * the complexType has a final of "extension".
 */
/*line: 466*/   XML_SCHEMAS_TYPE_FINAL_EXTENSION = 0x200,  // 1<<9
/**
 * XML_SCHEMAS_TYPE_FINAL_RESTRICTION:
 *
 * the simpleType/complexType has a final of "restriction".
 */
/*line: 472*/   XML_SCHEMAS_TYPE_FINAL_RESTRICTION = 0x400,  // 1<<10
/**
 * XML_SCHEMAS_TYPE_FINAL_LIST:
 *
 * the simpleType has a final of "list".
 */
/*line: 478*/   XML_SCHEMAS_TYPE_FINAL_LIST = 0x800,  // 1<<11
/**
 * XML_SCHEMAS_TYPE_FINAL_UNION:
 *
 * the simpleType has a final of "union".
 */
/*line: 484*/   XML_SCHEMAS_TYPE_FINAL_UNION = 0x1000,  // 1<<12
/**
 * XML_SCHEMAS_TYPE_FINAL_DEFAULT:
 *
 * the simpleType has a final of "default".
 */
/*line: 490*/   XML_SCHEMAS_TYPE_FINAL_DEFAULT = 0x2000,  // 1<<13
/**
 * XML_SCHEMAS_TYPE_BUILTIN_PRIMITIVE:
 *
 * Marks the item as a builtin primitive.
 */
/*line: 496*/   XML_SCHEMAS_TYPE_BUILTIN_PRIMITIVE = 0x4000,  // 1<<14
/**
 * XML_SCHEMAS_TYPE_MARKED:
 *
 * Marks the item as marked; used for circular checks.
 */
/*line: 502*/   XML_SCHEMAS_TYPE_MARKED = 0x10000,  // 1<<16
/**
 * XML_SCHEMAS_TYPE_BLOCK_DEFAULT:
 *
 * the complexType did not specify 'block' so use the default of the
 * <schema> item.
 */
/*line: 509*/   XML_SCHEMAS_TYPE_BLOCK_DEFAULT = 0x20000,  // 1<<17
/**
 * XML_SCHEMAS_TYPE_BLOCK_EXTENSION:
 *
 * the complexType has a 'block' of "extension".
 */
/*line: 515*/   XML_SCHEMAS_TYPE_BLOCK_EXTENSION = 0x40000,  // 1<<18
/**
 * XML_SCHEMAS_TYPE_BLOCK_RESTRICTION:
 *
 * the complexType has a 'block' of "restriction".
 */
/*line: 521*/   XML_SCHEMAS_TYPE_BLOCK_RESTRICTION = 0x80000,  // 1<<19
/**
 * XML_SCHEMAS_TYPE_ABSTRACT:
 *
 * the simple/complexType is abstract.
 */
/*line: 527*/   XML_SCHEMAS_TYPE_ABSTRACT = 0x100000,  // 1<<20
/**
 * XML_SCHEMAS_TYPE_FACETSNEEDVALUE:
 *
 * indicates if the facets need a computed value
 */
/*line: 533*/   XML_SCHEMAS_TYPE_FACETSNEEDVALUE = 0x200000,  // 1<<21
/**
 * XML_SCHEMAS_TYPE_INTERNAL_RESOLVED:
 *
 * indicates that the type was typefixed
 */
/*line: 539*/   XML_SCHEMAS_TYPE_INTERNAL_RESOLVED = 0x400000,  // 1<<22
/**
 * XML_SCHEMAS_TYPE_INTERNAL_INVALID:
 *
 * indicates that the type is invalid
 */
/*line: 545*/   XML_SCHEMAS_TYPE_INTERNAL_INVALID = 0x800000,  // 1<<23
/**
 * XML_SCHEMAS_TYPE_WHITESPACE_PRESERVE:
 *
 * a whitespace-facet value of "preserve"
 */
/*line: 551*/   XML_SCHEMAS_TYPE_WHITESPACE_PRESERVE = 0x1000000,  // 1<<24
/**
 * XML_SCHEMAS_TYPE_WHITESPACE_REPLACE:
 *
 * a whitespace-facet value of "replace"
 */
/*line: 557*/   XML_SCHEMAS_TYPE_WHITESPACE_REPLACE = 0x2000000,  // 1<<25
/**
 * XML_SCHEMAS_TYPE_WHITESPACE_COLLAPSE:
 *
 * a whitespace-facet value of "collapse"
 */
/*line: 563*/   XML_SCHEMAS_TYPE_WHITESPACE_COLLAPSE = 0x4000000,  // 1<<26
/**
 * XML_SCHEMAS_TYPE_HAS_FACETS:
 *
 * has facets
 */
/*line: 569*/   XML_SCHEMAS_TYPE_HAS_FACETS = 0x8000000,  // 1<<27
/**
 * XML_SCHEMAS_TYPE_NORMVALUENEEDED:
 *
 * indicates if the facets (pattern) need a normalized value
 */
/*line: 575*/   XML_SCHEMAS_TYPE_NORMVALUENEEDED = 0x10000000,  // 1<<28
};

enum macro_xml_schemas_type_fixup {
/**
 * XML_SCHEMAS_TYPE_FIXUP_1:
 *
 * First stage of fixup was done.
 */
/*line: 582*/   XML_SCHEMAS_TYPE_FIXUP_1 = 0x20000000,  // 1<<29
};

enum macro_type_redefined {
/**
 * XML_SCHEMAS_TYPE_REDEFINED:
 *
 * The type was redefined.
 */
/*line: 589*/   XML_SCHEMAS_TYPE_REDEFINED = 0x40000000,  // 1<<30
};

enum macro_element_flags {
/**
 * XML_SCHEMAS_ELEM_NILLABLE:
 *
 * the element is nillable
 */
/*line: 649*/   XML_SCHEMAS_ELEM_NILLABLE = 0x1,  // 1<<0
/**
 * XML_SCHEMAS_ELEM_GLOBAL:
 *
 * the element is global
 */
/*line: 655*/   XML_SCHEMAS_ELEM_GLOBAL = 0x2,  // 1<<1
/**
 * XML_SCHEMAS_ELEM_DEFAULT:
 *
 * the element has a default value
 */
/*line: 661*/   XML_SCHEMAS_ELEM_DEFAULT = 0x4,  // 1<<2
/**
 * XML_SCHEMAS_ELEM_FIXED:
 *
 * the element has a fixed value
 */
/*line: 667*/   XML_SCHEMAS_ELEM_FIXED = 0x8,  // 1<<3
/**
 * XML_SCHEMAS_ELEM_ABSTRACT:
 *
 * the element is abstract
 */
/*line: 673*/   XML_SCHEMAS_ELEM_ABSTRACT = 0x10,  // 1<<4
/**
 * XML_SCHEMAS_ELEM_TOPLEVEL:
 *
 * the element is top level
 * obsolete: use XML_SCHEMAS_ELEM_GLOBAL instead
 */
/*line: 680*/   XML_SCHEMAS_ELEM_TOPLEVEL = 0x20,  // 1<<5
/**
 * XML_SCHEMAS_ELEM_REF:
 *
 * the element is a reference to a type
 */
/*line: 686*/   XML_SCHEMAS_ELEM_REF = 0x40,  // 1<<6
/**
 * XML_SCHEMAS_ELEM_NSDEFAULT:
 *
 * allow elements in no namespace
 * Obsolete, not used anymore.
 */
/*line: 693*/   XML_SCHEMAS_ELEM_NSDEFAULT = 0x80,  // 1<<7
/**
 * XML_SCHEMAS_ELEM_INTERNAL_RESOLVED:
 *
 * this is set when "type", "ref", "substitutionGroup"
 * references have been resolved.
 */
/*line: 700*/   XML_SCHEMAS_ELEM_INTERNAL_RESOLVED = 0x100,  // 1<<8
/**
 * XML_SCHEMAS_ELEM_CIRCULAR:
 *
 * a helper flag for the search of circular references.
 */
/*line: 706*/   XML_SCHEMAS_ELEM_CIRCULAR = 0x200,  // 1<<9
/**
 * XML_SCHEMAS_ELEM_BLOCK_ABSENT:
 *
 * the "block" attribute is absent
 */
/*line: 712*/   XML_SCHEMAS_ELEM_BLOCK_ABSENT = 0x400,  // 1<<10
/**
 * XML_SCHEMAS_ELEM_BLOCK_EXTENSION:
 *
 * disallowed substitutions are absent
 */
/*line: 718*/   XML_SCHEMAS_ELEM_BLOCK_EXTENSION = 0x800,  // 1<<11
/**
 * XML_SCHEMAS_ELEM_BLOCK_RESTRICTION:
 *
 * disallowed substitutions: "restriction"
 */
/*line: 724*/   XML_SCHEMAS_ELEM_BLOCK_RESTRICTION = 0x1000,  // 1<<12
/**
 * XML_SCHEMAS_ELEM_BLOCK_SUBSTITUTION:
 *
 * disallowed substitutions: "substitution"
 */
/*line: 730*/   XML_SCHEMAS_ELEM_BLOCK_SUBSTITUTION = 0x2000,  // 1<<13
/**
 * XML_SCHEMAS_ELEM_FINAL_ABSENT:
 *
 * substitution group exclusions are absent
 */
/*line: 736*/   XML_SCHEMAS_ELEM_FINAL_ABSENT = 0x4000,  // 1<<14
/**
 * XML_SCHEMAS_ELEM_FINAL_EXTENSION:
 *
 * substitution group exclusions: "extension"
 */
/*line: 742*/   XML_SCHEMAS_ELEM_FINAL_EXTENSION = 0x8000,  // 1<<15
/**
 * XML_SCHEMAS_ELEM_FINAL_RESTRICTION:
 *
 * substitution group exclusions: "restriction"
 */
/*line: 748*/   XML_SCHEMAS_ELEM_FINAL_RESTRICTION = 0x10000,  // 1<<16
/**
 * XML_SCHEMAS_ELEM_SUBST_GROUP_HEAD:
 *
 * the declaration is a substitution group head
 */
/*line: 754*/   XML_SCHEMAS_ELEM_SUBST_GROUP_HEAD = 0x20000,  // 1<<17
/**
 * XML_SCHEMAS_ELEM_INTERNAL_CHECKED:
 *
 * this is set when the elem decl has been checked against
 * all constraints
 */
/*line: 761*/   XML_SCHEMAS_ELEM_INTERNAL_CHECKED = 0x40000,  // 1<<18
};

enum macro_facet_handling {
/*
 * XML_SCHEMAS_FACET_UNKNOWN:
 *
 * unknown facet handling
 */
/*line: 801*/   XML_SCHEMAS_FACET_UNKNOWN = 0x0,  // 0
/*
 * XML_SCHEMAS_FACET_PRESERVE:
 *
 * preserve the type of the facet
 */
/*line: 807*/   XML_SCHEMAS_FACET_PRESERVE = 0x1,  // 1
/*
 * XML_SCHEMAS_FACET_REPLACE:
 *
 * replace the type of the facet
 */
/*line: 813*/   XML_SCHEMAS_FACET_REPLACE = 0x2,  // 2
/*
 * XML_SCHEMAS_FACET_COLLAPSE:
 *
 * collapse the types of the facet
 */
/*line: 819*/   XML_SCHEMAS_FACET_COLLAPSE = 0x3,  // 3
};

enum macro_schema_flags {
/**
 * XML_SCHEMAS_QUALIF_ELEM:
 *
 * Reflects elementFormDefault == qualified in
 * an XML schema document.
 */
/*line: 861*/   XML_SCHEMAS_QUALIF_ELEM = 0x1,  // 1<<0
/**
 * XML_SCHEMAS_QUALIF_ATTR:
 *
 * Reflects attributeFormDefault == qualified in
 * an XML schema document.
 */
/*line: 868*/   XML_SCHEMAS_QUALIF_ATTR = 0x2,  // 1<<1
/**
 * XML_SCHEMAS_FINAL_DEFAULT_EXTENSION:
 *
 * the schema has "extension" in the set of finalDefault.
 */
/*line: 874*/   XML_SCHEMAS_FINAL_DEFAULT_EXTENSION = 0x4,  // 1<<2
/**
 * XML_SCHEMAS_FINAL_DEFAULT_RESTRICTION:
 *
 * the schema has "restriction" in the set of finalDefault.
 */
/*line: 880*/   XML_SCHEMAS_FINAL_DEFAULT_RESTRICTION = 0x8,  // 1<<3
/**
 * XML_SCHEMAS_FINAL_DEFAULT_LIST:
 *
 * the schema has "list" in the set of finalDefault.
 */
/*line: 886*/   XML_SCHEMAS_FINAL_DEFAULT_LIST = 0x10,  // 1<<4
/**
 * XML_SCHEMAS_FINAL_DEFAULT_UNION:
 *
 * the schema has "union" in the set of finalDefault.
 */
/*line: 892*/   XML_SCHEMAS_FINAL_DEFAULT_UNION = 0x20,  // 1<<5
/**
 * XML_SCHEMAS_BLOCK_DEFAULT_EXTENSION:
 *
 * the schema has "extension" in the set of blockDefault.
 */
/*line: 898*/   XML_SCHEMAS_BLOCK_DEFAULT_EXTENSION = 0x40,  // 1<<6
/**
 * XML_SCHEMAS_BLOCK_DEFAULT_RESTRICTION:
 *
 * the schema has "restriction" in the set of blockDefault.
 */
/*line: 904*/   XML_SCHEMAS_BLOCK_DEFAULT_RESTRICTION = 0x80,  // 1<<7
/**
 * XML_SCHEMAS_BLOCK_DEFAULT_SUBSTITUTION:
 *
 * the schema has "substitution" in the set of blockDefault.
 */
/*line: 910*/   XML_SCHEMAS_BLOCK_DEFAULT_SUBSTITUTION = 0x100,  // 1<<8
/**
 * XML_SCHEMAS_INCLUDING_CONVERT_NS:
 *
 * the schema is currently including an other schema with
 * no target namespace.
 */
/*line: 917*/   XML_SCHEMAS_INCLUDING_CONVERT_NS = 0x200,  // 1<<9
};

