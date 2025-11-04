// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/membership.h

enum macro_id_type {
/*!
	@defined    ID_TYPE_UID
	@abstract   is of type uid_t
	@discussion is of type uid_t
*/
/*line: 34*/    ID_TYPE_UID = 0x0,  // 0
/*!
	@defined    ID_TYPE_GID
	@abstract   is of type gid_t
	@discussion is of type gid_t
*/
/*line: 41*/    ID_TYPE_GID = 0x1,  // 1
/*!
    @defined    ID_TYPE_SID
    @abstract   is of type ntsid_t
    @discussion is of type ntsid_t
*/
/*line: 48*/    ID_TYPE_SID = 0x3,  // 3
/*!
    @defined    ID_TYPE_USERNAME
    @abstract   is a NULL terminated UTF8 string
    @discussion is a NULL terminated UTF8 string
*/
/*line: 55*/    ID_TYPE_USERNAME = 0x4,  // 4
/*!
    @defined    ID_TYPE_GROUPNAME
    @abstract   is a NULL terminated UTF8 string
    @discussion is a NULL terminated UTF8 string
*/
/*line: 62*/    ID_TYPE_GROUPNAME = 0x5,  // 5
/*!
	@defined	ID_TYPE_UUID
	@abstract	is of type uuid_t
	@discussion	is of type uuid_t
*/
/*line: 69*/    ID_TYPE_UUID = 0x6,  // 6
/*!
    @defined    ID_TYPE_GROUP_NFS
    @abstract   is a NULL terminated UTF8 string
    @discussion is a NULL terminated UTF8 string
*/
/*line: 76*/    ID_TYPE_GROUP_NFS = 0x7,  // 7
/*!
    @defined    ID_TYPE_USER_NFS
    @abstract   is a NULL terminated UTF8 string
    @discussion is a NULL terminated UTF8 string
*/
/*line: 83*/    ID_TYPE_USER_NFS = 0x8,  // 8
/*!
	@defined    ID_TYPE_GSS_EXPORT_NAME
	@abstract	is a gss exported name
	@discussion	is the data in gss_buffer_t as returned from gss_export_name.
*/
/*line: 90*/    ID_TYPE_GSS_EXPORT_NAME = 0xa,  // 10
/*!
	@defined    ID_TYPE_X509_DN
	@abstract	is a NULL terminated string representation of the X.509 certificate identity
	@discussion	is a NULL terminated string with the format of:
 
				<I>DN of the Certificate authority<S>DN of the holder
 
				Example:
 
				<I>DC=com,DC=example,CN=CertificatAuthority<S>DC=com,DC=example,CN=username
*/
/*line: 103*/   ID_TYPE_X509_DN = 0xb,  // 11
/*!
	@defined    ID_TYPE_KERBEROS
	@abstract	is a NULL terminated string representation of a Kerberos principal
	@discussion	is a NULL terminated string in the form of user\@REALM representing a typical 
				Kerberos principal.
*/
/*line: 111*/   ID_TYPE_KERBEROS = 0xc,  // 12
};

