/*
 * =====================================================================================
 *
 *       Filename:  mapi.c
 *
 *    Description:  implement fetchmail's interface for new protocols in MAPI
 *
 *        Version:  
 *        Created:  07/01/08 10:08:27
 *       Revision:  
 *       Compiler:  
 *
 *         Author:  Yangyan Li (), yangyan.li1986@gmail.com
 *        Company:  Shenzhen Institute of Advanced Technology, CAS
 *
 * =====================================================================================
 */

// TODO: write copyright stuff here

#include  "config.h"
#ifdef MAPI_ENABLE
#include  <stdio.h>
#include  <string.h>
#include  <ctype.h>
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#if defined(STDC_HEADERS)
#include  <stdlib.h>
#endif
#include  <errno.h>

#include  <libmapi/libmapi.h>
#include <magic.h>

#include  "fetchmail.h"
#include  "socket.h"
#include  "i18n.h"

#define DEFAULT_MAPI_PROFILES "%s/.fetchmail_mapi_profiles.ldb"

static TALLOC_CTX *mapi_mem_ctx;
static struct mapi_profile *mapi_profile;
static mapi_object_t mapi_obj_store;
static mapi_object_t mapi_obj_inbox;
static mapi_object_t mapi_obj_table;
static mapi_id_array_t mapi_deleted_ids;
static struct SRowSet mapi_rowset;
static int      mapi_initialized = FALSE;
/*
 * as said in fetchmail.h, these should be of size PATH_MAX 
 */
static char     mapi_profdb[1024];	/* mapi profiles databse */
static char     password[128];


static DATA_BLOB mapi_buffer;
static int      mapi_buffer_count;


#if defined(HAVE_STDARG_H)
void
MapiWrite(int *lenp, const char *format, ...)
{
#else
void
MapiWrite(lenp, format, va_alist)
    int            *lenp;
    char           *format;
    va_dcl
{
#endif

    va_list         ap;
    char           *temp_line;
#if defined(HAVE_STDARG_H)
    va_start(ap, format);
#else
    va_start(ap);
#endif
    temp_line = talloc_vasprintf(mapi_mem_ctx, format, ap);
    data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
    *lenp += strlen(temp_line);
    talloc_free(temp_line);
    va_end(ap);

    return;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  MapiRead
 *  Description:  match the interface of SockRead in socket.h to feed the driver with
 *                MAPI data.
 * =====================================================================================
 */
int
MapiRead(int sock, char *buf, int len)
{
    int             count = 0;

    while (mapi_buffer_count < mapi_buffer.length) {
	*(buf + count) = *(mapi_buffer.data + mapi_buffer_count);
	count++;
	mapi_buffer_count++;
	if (*(buf + count - 1) == '\n') {
	    *(buf + count) = '\0';
	    return count;
	}
	if (count == len - 1) {
	    *(buf + count) = '\0';
	    return count;
	}
    }

    return -1;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  MapiPeek
 *  Description:  match the interface to SockPeek.
 * =====================================================================================
 */
int
MapiPeek(int sock)
{
    if (mapi_buffer_count < mapi_buffer.length)
	return *(mapi_buffer.data + mapi_buffer_count);
    else
	return -1;
}



static const char *
get_filename(const char *filename)
{
    const char     *substr;

    if (!filename)
	return NULL;

    substr = rindex(filename, '/');
    if (substr)
	return substr;

    return filename;
}

/*
 * encode as base64 Samba4 code caller frees 
 */
static char    *
ldb_base64_encode(void *mem_ctx, const char *buf, int len)
{
    const char     *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int             bit_offset;
    int             byte_offset;
    int             idx;
    int             i;
    const uint8_t  *d = (const uint8_t *) buf;
    int             bytes = (len * 8 + 5) / 6;
    int             pad_bytes = (bytes % 4) ? 4 - (bytes % 4) : 0;
    char           *out;

    out = talloc_array(mem_ctx, char, bytes + pad_bytes + 1);
    if (!out)
	return NULL;

    for (i = 0; i < bytes; i++) {
	byte_offset = (i * 6) / 8;
	bit_offset = (i * 6) % 8;
	if (bit_offset < 3) {
	    idx = (d[byte_offset] >> (2 - bit_offset)) & 0x3F;
	} else {
	    idx = (d[byte_offset] << (bit_offset - 2)) & 0x3F;
	    if (byte_offset + 1 < len) {
		idx |= (d[byte_offset + 1] >> (8 - (bit_offset - 2)));
	    }
	}
	out[i] = b64[idx];
    }

    for (; i < bytes + pad_bytes; i++)
	out[i] = '=';
    out[i] = 0;

    return out;
}


static char    *
get_base64_attachment(TALLOC_CTX * mem_ctx, mapi_object_t obj_attach, const uint32_t size, char **magic)
{
    enum MAPISTATUS retval;
    const char     *tmp;
    mapi_object_t   obj_stream;
    uint32_t        stream_size;
    uint32_t        read_size;
    unsigned char   buf[MSGBUFSIZE];
    uint32_t        max_read_size = MSGBUFSIZE;
    DATA_BLOB       data;
    magic_t         cookie = NULL;

    retval = OpenStream(&obj_attach, PR_ATTACH_DATA_BIN, 0, &obj_stream);
    if (retval != MAPI_E_SUCCESS)
	return false;

    retval = GetStreamSize(&obj_stream, &data.length);
    if (retval != MAPI_E_SUCCESS)
	return false;
    data.data = talloc_size(mem_ctx, data.length);

    read_size = size;
    for (stream_size = 0; stream_size < data.length && read_size != 0; stream_size += MSGBUFSIZE) {
	retval = ReadStream(&obj_stream, buf, max_read_size, &read_size);
	if (retval != MAPI_E_SUCCESS)
	    return NULL;
	memcpy(data.data, buf, read_size);
    }

    cookie = magic_open(MAGIC_MIME);
    if (cookie == NULL) {
	printf("%s\n", magic_error(cookie));
	return NULL;
    }
    if (magic_load(cookie, NULL) == -1) {
	printf("%s\n", magic_error(cookie));
	return NULL;
    }
    tmp = magic_buffer(cookie, (void *) data.data, data.length);
    *magic = talloc_strdup(mem_ctx, tmp);
    magic_close(cookie);

    /*
     * convert attachment to base64 
     */
    return (ldb_base64_encode(mem_ctx, (const char *) data.data, data.length));
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  is_safe_char
 *  Description:  check if a character is safe to be represented as the ASCII character.
 * =====================================================================================
 */
static int
is_safe_char(char ch)
{
	/*-----------------------------------------------------------------------------
	 *  For total robustness, it is better to quote every character except for the
	 *  73-character set known to be invariant across all gateways, that is the 
	 *  letters anddigits (A-Z, a-z and 0-9) and the following 11 characters:
	 *  ' ( ) + , - . / : = ?
	 *-----------------------------------------------------------------------------*/
    return isalnum(ch) || ch == '\'' || ch == '(' || ch == ')' || ch == '+' || ch == ','
	|| ch == '-' || ch == '.' || ch == '/' || ch == ':' || ch == '=' || ch == '?';
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  quoted_printable_encode
 *  Description:  encode the body and append it to mapi_buffer 
 * =====================================================================================
 */
static void
quoted_printable_encode(const DATA_BLOB * body, int *lenp)
{
    int             line_count = 0;
    int             body_count = 0;
    char            hex[16] = "0123456789ABCDEF";
    char            ch;
    char            line[78];

    while (body_count < body->length) {
	ch = *(body->data + body_count);
	body_count++;

	if (is_safe_char(ch))
	    line[line_count++] = ch;
	else {
	    line[line_count++] = '=';
	    line[line_count++] = hex[(ch >> 4) & 15];
	    line[line_count++] = hex[ch & 15];
	}

	if (line_count >= 73 || ch == '\n') {
	    if (ch != '\n')
		line[line_count++] = '=';
	    line[line_count++] = '\r';
	    line[line_count] = '\n';

	    data_blob_append(mapi_mem_ctx, &mapi_buffer, line, line_count);
	    *lenp += line_count;

	    line_count = 0;
	}
    }
    if (line_count != 0) {
	line[line_count++] = '\r';
	line[line_count] = '\n';
	data_blob_append(mapi_mem_ctx, &mapi_buffer, line, line_count);
	*lenp += line_count;
    }
}

static void
mapi_clean()
{
    mapi_object_release(&mapi_obj_table);
    mapi_object_release(&mapi_obj_inbox);
    mapi_object_release(&mapi_obj_store);
    MAPIUninitialize();
    talloc_free(mapi_mem_ctx);

    mapi_initialized = FALSE;
}

static int
mapi_init(const char *folder)
{
    enum MAPISTATUS retval;
    struct mapi_session *session = NULL;
    int             ok = MAPI_E_SUCCESS;
    mapi_id_t       id_folder;
    struct SPropTagArray *SPropTagArray = NULL;
    const char     *profname;
    uint32_t        count;

    mapi_mem_ctx = talloc_init("fetchmail");

    /*-----------------------------------------------------------------------------
     *  Initialize MAPI subsystem
     *-----------------------------------------------------------------------------*/
    retval = MAPIInitialize(mapi_profdb);
    if (retval != MAPI_E_SUCCESS) {
	report(stderr, GT_("MAPI: MAPIInitialize failed\n"));
	ok = GetLastError();
	mapi_clean();
	return ok;
    }

    /*-----------------------------------------------------------------------------
     *  use the default mapi_profile
     *-----------------------------------------------------------------------------*/
    retval = GetDefaultProfile(&profname);
    if (retval != MAPI_E_SUCCESS) {
	report(stderr, GT_("MAPI: GetDefaultProfile failed\n"));
	ok = GetLastError();
	mapi_clean();
	return ok;
    }

    retval = MapiLogonEx(&session, profname, password);
    if (retval != MAPI_E_SUCCESS) {
	report(stderr, GT_("MAPI: MapiLogonEx failed\n"));
	ok = GetLastError();
	mapi_clean();
	return ok;
    }
    mapi_profile = session->profile;


    /*-----------------------------------------------------------------------------
     *  Open the default message store
     *-----------------------------------------------------------------------------*/
    mapi_object_init(&mapi_obj_store);
    retval = OpenMsgStore(&mapi_obj_store);
    if (retval != MAPI_E_SUCCESS) {
	report(stderr, GT_("MAPI: OpenMsgStore failed\n"));
	ok = GetLastError();
	mapi_clean();
	return ok;
    }

    /*-----------------------------------------------------------------------------
     *  Open folder
     *  TODO: open folder specified by --folder option
     *-----------------------------------------------------------------------------*/

    /*-----------------------------------------------------------------------------
     *  open inbox by default
     *-----------------------------------------------------------------------------*/
    retval = GetDefaultFolder(&mapi_obj_store, &id_folder, olFolderInbox);
    if (retval != MAPI_E_SUCCESS) {
	report(stderr, GT_("MAPI: OpenMsgStore failed\n"));
	ok = GetLastError();
	mapi_clean();
	return ok;
    }

    mapi_object_init(&mapi_obj_inbox);
    retval = OpenFolder(&mapi_obj_store, id_folder, &mapi_obj_inbox);
    if (retval != MAPI_E_SUCCESS) {
	report(stderr, GT_("MAPI: OpenMsgStore failed\n"));
	ok = GetLastError();
	mapi_clean();
	return ok;
    }

    mapi_object_init(&mapi_obj_table);
    retval = GetContentsTable(&mapi_obj_inbox, &mapi_obj_table, 0, &count);
    if (retval != MAPI_E_SUCCESS) {
	report(stderr, GT_("MAPI: OpenMsgStore failed\n"));
	ok = GetLastError();
	mapi_clean();
	return ok;
    }

    SPropTagArray = set_SPropTagArray(mapi_mem_ctx, 0x2, PR_FID, PR_MID);
    retval = SetColumns(&mapi_obj_table, SPropTagArray);
    MAPIFreeBuffer(SPropTagArray);
    if (retval != MAPI_E_SUCCESS) {
	report(stderr, GT_("MAPI: OpenMsgStore failed\n"));
	ok = GetLastError();
	mapi_clean();
	return ok;
    }

    retval = QueryRows(&mapi_obj_table, count, TBL_ADVANCE, &mapi_rowset);
    if (retval != MAPI_E_SUCCESS) {
	ok = GetLastError();
	mapi_clean();
	return ok;
    }

    mapi_id_array_init(&mapi_deleted_ids);
    mapi_initialized = TRUE;
    return ok;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  translate_mapi_error
 *  Description:  translate mapi error code into fetchmail error code
 * =====================================================================================
 */
static int
translate_mapi_error(enum MAPISTATUS mapi_error)
{
    switch (mapi_error) {
    case MAPI_E_SUCCESS:
	return PS_SUCCESS;
    case MAPI_E_CALL_FAILED:
    case MAPI_E_NO_SUPPORT:
    case MAPI_E_BAD_CHARWIDTH:
    case MAPI_E_STRING_TOO_LONG:
    case MAPI_E_UNKNOWN_FLAGS:
    case MAPI_E_INVALID_ENTRYID:
    case MAPI_E_INVALID_OBJECT:
    case MAPI_E_OBJECT_CHANGED:
    case MAPI_E_OBJECT_DELETED:
    case MAPI_E_BUSY:
    case MAPI_E_NOT_ENOUGH_DISK:
    case MAPI_E_NOT_ENOUGH_RESOURCES:
    case MAPI_E_NOT_FOUND:
    case MAPI_E_VERSION:
    case MAPI_E_LOGON_FAILED:
    case MAPI_E_SESSION_LIMIT:
    case MAPI_E_USER_CANCEL:
    case MAPI_E_UNABLE_TO_ABORT:
    case MAPI_E_NETWORK_ERROR:
    case MAPI_E_DISK_ERROR:
    case MAPI_E_TOO_COMPLEX:
    case MAPI_E_BAD_COLUMN:
    case MAPI_E_EXTENDED_ERROR:
    case MAPI_E_COMPUTED:
    case MAPI_E_CORRUPT_DATA:
    case MAPI_E_UNCONFIGURED:
    case MAPI_E_FAILONEPROVIDER:
    case MAPI_E_UNKNOWN_CPID:
    case MAPI_E_UNKNOWN_LCID:
    case MAPI_E_PASSWORD_CHANGE_REQUIRED:
    case MAPI_E_PASSWORD_EXPIRED:
    case MAPI_E_INVALID_WORKSTATION_ACCOUNT:
    case MAPI_E_INVALID_ACCESS_TIME:
    case MAPI_E_ACCOUNT_DISABLED:
    case MAPI_E_END_OF_SESSION:
    case MAPI_E_UNKNOWN_ENTRYID:
    case MAPI_E_MISSING_REQUIRED_COLUMN:
    case MAPI_W_NO_SERVICE:
    case MAPI_E_BAD_VALUE:
    case MAPI_E_INVALID_TYPE:
    case MAPI_E_TYPE_NO_SUPPORT:
    case MAPI_E_UNEXPECTED_TYPE:
    case MAPI_E_TOO_BIG:
    case MAPI_E_DECLINE_COPY:
    case MAPI_E_UNEXPECTED_ID:
    case MAPI_W_ERRORS_RETURNED:
    case MAPI_E_UNABLE_TO_COMPLETE:
    case MAPI_E_TIMEOUT:
    case MAPI_E_TABLE_EMPTY:
    case MAPI_E_TABLE_TOO_BIG:
    case MAPI_E_INVALID_BOOKMARK:
    case MAPI_W_POSITION_CHANGED:
    case MAPI_W_APPROX_COUNT:
    case MAPI_E_WAIT:
    case MAPI_E_CANCEL:
    case MAPI_E_NOT_ME:
    case MAPI_W_CANCEL_MESSAGE:
    case MAPI_E_CORRUPT_STORE:
    case MAPI_E_NOT_IN_QUEUE:
    case MAPI_E_NO_SUPPRESS:
    case MAPI_E_COLLISION:
    case MAPI_E_NOT_INITIALIZED:
    case MAPI_E_NON_STANDARD:
    case MAPI_E_NO_RECIPIENTS:
    case MAPI_E_SUBMITTED:
    case MAPI_E_HAS_FOLDERS:
    case MAPI_E_HAS_MESAGES:
    case MAPI_E_FOLDER_CYCLE:
    case MAPI_W_PARTIAL_COMPLETION:
    case MAPI_E_AMBIGUOUS_RECIP:
    case MAPI_E_NO_ACCESS:
    case MAPI_E_INVALID_PARAMETER:
    case MAPI_E_RESERVED:
    default:
	return PS_UNDEFINED;
    }
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  expunge_deleted
 *  Description:  
 * =====================================================================================
 */
static int
expunge_deleted()
{
    enum MAPISTATUS retval;
    mapi_id_t      *deleted_ids;

    if (mapi_deleted_ids.count == 0)
	return (PS_SUCCESS);
    /*-----------------------------------------------------------------------------
     *  perform hard delete
     *-----------------------------------------------------------------------------*/
    mapi_id_array_get(mapi_mem_ctx, &mapi_deleted_ids, &deleted_ids);
    retval = DeleteMessage(&mapi_obj_inbox, deleted_ids, mapi_deleted_ids.count);
    if (retval != MAPI_E_SUCCESS) {
	report(stderr, "MAPI: DeleteMessages failed\n");
	talloc_free(deleted_ids);
	return translate_mapi_error(GetLastError());
    }
    talloc_free(deleted_ids);
    return (PS_SUCCESS);
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_ok
 *  Description:  no need to parse response in MAPI, return PS_SUCCESS to fake the driver
 * =====================================================================================
 */
static int
mapi_ok(int sock, char *argbuf)
{
    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_ok()\n");

    return PS_SUCCESS;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  callback
 *  Description:  when not running in daemon mode, give a chance to choose an account
 *                while multiple accounts match the user name.
 *                when running in daemon mode, skip this and get_auth will return
 *                PS_AUTHFAIL.
 * =====================================================================================
 */
static          uint32_t
callback(struct SRowSet *rowset, void *private)
{
    // TODO: check if running in daemon mode
    int             daemon_mode = FALSE;

    if (!daemon_mode) {
	uint32_t        i;
	struct SPropValue *lpProp;
	FILE           *fd;
	uint32_t        index;
	char            entry[10];
	const char     *label = (const char *) private;

	printf("%s:\n", label);
	for (i = 0; i < rowset->cRows; i++) {
	    lpProp = get_SPropValue_SRow(&(rowset->aRow[i]), PR_DISPLAY_NAME);
	    if (lpProp && lpProp->value.lpszA) {
		printf("\t[%d] %s\n", i, lpProp->value.lpszA);
	    }
	}
	printf("\t[%d] cancel operation\n", i);
	fd = fdopen(0, "r");
      getentry:
	printf("Enter username id [0]: ");
	fgets(entry, 10, fd);
	index = atoi(entry);
	if (index > i) {
	    printf("Invalid id - Must be contained between 0 and %d\n", i);
	    goto getentry;
	}

	fclose(fd);
	return (index);
    } else
	return rowset->cRows;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_getauth
 *  Description:  1. synchronize mapi_profile with the setting
 *                2. open the mapi_profile and initialize MAPI
 *                if all of the operations are successful, it will be considered
 *                a successful anthentication. 
 * =====================================================================================
 */
static int
mapi_getauth(int sock, struct query *ctl, char *greeting)
{
    enum MAPISTATUS retval;
    struct mapi_session *session = NULL;
    struct SRowSet  proftable;
    int             profcount;
    char            localhost_name[256];
    const char     *workstation = NULL;
    const char     *ldif = NULL;
    const char     *profname = NULL;
    const char     *name_in_proftable = NULL;
    uint32_t        flags;
    char           *realhost = ctl->server.via ? ctl->server.via : ctl->server.pollname;

    if (outlevel > O_MONITOR)
	report(stdout, "MAPI> mapi_getauth()\n");

    mapi_mem_ctx = talloc_init("mapi_getauth");
    /*-----------------------------------------------------------------------------
     *  initialize several options
     *-----------------------------------------------------------------------------*/
    strcpy(password, ctl->password);
    if (!ctl->mapi_ldif)
	ldif = talloc_strdup(mapi_mem_ctx, mapi_profile_get_ldif_path());
    else
	ldif = ctl->mapi_ldif;

    if (!ctl->mapi_profname)
	profname = ctl->remotename;	/* use the remotename as the profile name */
    else
	profname = ctl->mapi_profname;

    if (!ctl->mapi_profdb)
	sprintf(mapi_profdb, DEFAULT_MAPI_PROFILES, getenv("HOME"));
    else
	strcpy(mapi_profdb, ctl->mapi_profdb);

    if (!ctl->mapi_workstation) {
	gethostname(localhost_name, sizeof(localhost_name) - 1);
	localhost_name[sizeof(localhost_name) - 1] = 0;
	workstation = localhost_name;
    } else
	workstation = ctl->mapi_workstation;

    /*-----------------------------------------------------------------------------
     *  mapi_domain is a required option! how to check if it is specified?
     *  if not specified, default values of workstation, ldif and mapi_lcid (set in 
     *  fetchmail.c) are used
     *-----------------------------------------------------------------------------*/
    if (!ctl->mapi_domain || !workstation || !ldif || !ctl->mapi_lcid) {
	talloc_free(mapi_mem_ctx);
	return PS_AUTHFAIL;
    }


    if (access(mapi_profdb, F_OK) != 0) {
    /*-----------------------------------------------------------------------------
     *  create mapi mapi_profile database
     *-----------------------------------------------------------------------------*/
	retval = CreateProfileStore(mapi_profdb, ldif);
	if (retval != MAPI_E_SUCCESS) {
	    talloc_free(mapi_mem_ctx);
	    return translate_mapi_error(GetLastError());
	}
	if (outlevel == O_DEBUG)
	    report(stdout, GT_("MAPI> MAPI mapi_profile database %s created\n"), mapi_profdb);
    }

    retval = MAPIInitialize(mapi_profdb);
    if (retval != MAPI_E_SUCCESS)
	goto clean;
    if (outlevel == O_DEBUG)
	report(stdout, GT_("MAPI> MAPI initialized\n"));

    memset(&proftable, 0, sizeof(struct SRowSet));
    retval = GetProfileTable(&proftable);
    if (retval != MAPI_E_SUCCESS)
	goto clean;
    if (outlevel == O_DEBUG)
	report(stdout, GT_("MAPI> MAPI GetProfiletable\n"));


    for (profcount = 0; profcount != proftable.cRows; profcount++) {
	name_in_proftable = proftable.aRow[profcount].lpProps[0].value.lpszA;
	if (strcmp(name_in_proftable, profname) == 0)
	    break;
    }

    if (profcount == proftable.cRows) {
	flags = 0;		/* do not save password in the mapi_profile */
	retval = CreateProfile(profname, ctl->remotename, password, flags);
	if (retval != MAPI_E_SUCCESS)
	    goto clean;

	mapi_profile_add_string_attr(profname, "binding", realhost);
	mapi_profile_add_string_attr(profname, "workstation", workstation);
	mapi_profile_add_string_attr(profname, "domain", ctl->mapi_domain);
	mapi_profile_add_string_attr(profname, "codepage", "0x4e4");
	mapi_profile_add_string_attr(profname, "language", ctl->mapi_lcid);
	mapi_profile_add_string_attr(profname, "method", "0x409");
	if (outlevel == O_DEBUG)
	    report(stdout, GT_("MAPI> MAPI mapi_profile %s created\n"), profname);
    } else {
	mapi_profile_modify_string_attr(profname, "binding", realhost);
	mapi_profile_modify_string_attr(profname, "workstation", workstation);
	mapi_profile_modify_string_attr(profname, "domain", ctl->mapi_domain);
	mapi_profile_modify_string_attr(profname, "codepage", "0x4e4");
	mapi_profile_modify_string_attr(profname, "language", ctl->mapi_lcid);
	mapi_profile_modify_string_attr(profname, "method", "0x409");

	if (outlevel == O_DEBUG)
	    report(stdout, GT_("MAPI> MAPI mapi_profile %s updated\n"), profname);
    }


    retval = MapiLogonProvider(&session, profname, password, PROVIDER_ID_NSPI);
    if (retval != MAPI_E_SUCCESS)
	goto clean;
    if (outlevel == O_DEBUG)
	report(stdout, GT_("MAPI> MapiLogonProvider\n"));


    retval = ProcessNetworkProfile(session, ctl->remotename, (mapi_profile_callback_t) callback, "Select a user id");
    if (retval != MAPI_E_SUCCESS)
	goto clean;
    if (outlevel == O_DEBUG)
	report(stdout, GT_("MAPI> processed a full and automated MAPI mapi_profile creation\n"));


    retval = SetDefaultProfile(profname);
    if (retval != MAPI_E_SUCCESS)
	goto clean;
    if (outlevel == O_DEBUG)
	report(stdout, GT_("MAPI> set default mapi_profile to %s\n"), profname);

    MAPIUninitialize();
    talloc_free(mapi_mem_ctx);
    return PS_SUCCESS;

  clean:MAPIUninitialize();
    talloc_free(mapi_mem_ctx);
    return translate_mapi_error(GetLastError());
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_getrange
 *  Description:  get range of messages to be fetched
 * =====================================================================================
 */
static int
mapi_getrange(int sock, struct query *ctl, const char *folder, int *countp, int *newp, int *bytes)
{
    enum MAPISTATUS retval;
    int             ok = PS_SUCCESS;
    struct SPropTagArray *SPropTagArray = NULL;
    struct SPropValue *lpProps;
    struct SRow     aRow;
    const char     *msgid;
    int             props_count;
    mapi_object_t   obj_message;
    mapi_id_t      *fid;
    mapi_id_t      *mid;
    int             i;

    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_getrange()\n");

    *countp = 0;
    *newp = 0;
    *bytes = 0;


    /*-----------------------------------------------------------------------------
     * initialize mapi here
     *-----------------------------------------------------------------------------*/
    ok = mapi_init(NULL);
    if (ok) {
	report(stderr, GT_("MAPI: MAPI is not initialized\n"));
	return (PS_UNDEFINED);
    }

    *countp = mapi_rowset.cRows;

    for (i = 0; i < mapi_rowset.cRows; i++) {
	fid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[i]), PR_FID);
	mid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[i]), PR_MID);
	mapi_object_init(&obj_message);

	retval = OpenMessage(&mapi_obj_store, *fid, *mid, &obj_message, 0x0);

	if (retval == MAPI_E_SUCCESS) {
	    SPropTagArray = set_SPropTagArray(mapi_mem_ctx, 0x3, PR_INTERNET_MESSAGE_ID, PR_MESSAGE_FLAGS, PR_MESSAGE_SIZE);
	    retval = GetProps(&obj_message, SPropTagArray, &lpProps, &props_count);
	    MAPIFreeBuffer(SPropTagArray);
	    if (retval != MAPI_E_SUCCESS) {
		ok = translate_mapi_error(GetLastError());
		talloc_free(lpProps);
		mapi_object_release(&obj_message);
		mapi_clean();
		return ok;
	    }

	    /*-----------------------------------------------------------------------------
	     *  build a SRow structure
	     *-----------------------------------------------------------------------------*/
	    aRow.ulAdrEntryPad = 0;
	    aRow.cValues = props_count;
	    aRow.lpProps = lpProps;

	    msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
	    long            message_flags = *(const long *) find_SPropValue_data(&aRow,
										 PR_MESSAGE_FLAGS);
	    if (msgid && !(message_flags & MSGFLAG_READ)) {
		(*newp)++;
		(*bytes)
		    += *(const long *)
		    find_SPropValue_data(&aRow, PR_MESSAGE_SIZE);
	    }
	    talloc_free(lpProps);
	}
	mapi_object_release(&obj_message);
    }

    return PS_SUCCESS;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_getpartialsizes
 *  Description:  capture the sizes of messages #first-#last
 * =====================================================================================
 */
static int
mapi_getpartialsizes(int sock, int first, int last, int *sizes)
{
    enum MAPISTATUS retval;
    int             ok = PS_SUCCESS;
    struct SPropTagArray *SPropTagArray = NULL;
    struct SPropValue *lpProps;
    struct SRow     aRow;
    int             props_count;
    mapi_object_t   obj_message;
    const char     *msgid;
    mapi_id_t      *fid;
    mapi_id_t      *mid;
    int             i;

    if (first != -1) {
	if (outlevel >= O_MONITOR)
	    report(stdout, "MAPI> mapi_getpartialsizes(first %d, last %d)\n", first, last);
    } else
	first = 1;

    if (!mapi_initialized) {
	report(stderr, GT_("MAPI: MAPI is not initialized\n"));
	return (PS_UNDEFINED);
    }

    for (i = first; i <= mapi_rowset.cRows && i <= last; i++) {
	fid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[i - 1]), PR_FID);
	mid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[i - 1]), PR_MID);
	mapi_object_init(&obj_message);

	retval = OpenMessage(&mapi_obj_store, *fid, *mid, &obj_message, 0x0);

	if (retval == MAPI_E_SUCCESS) {
	    SPropTagArray = set_SPropTagArray(mapi_mem_ctx, 0x2, PR_INTERNET_MESSAGE_ID, PR_MESSAGE_SIZE);
	    retval = GetProps(&obj_message, SPropTagArray, &lpProps, &props_count);
	    MAPIFreeBuffer(SPropTagArray);
	    if (retval != MAPI_E_SUCCESS) {
		ok = translate_mapi_error(GetLastError());
		talloc_free(lpProps);
		mapi_object_release(&obj_message);
		mapi_clean();
		return ok;
	    }

	    /*
	     * Build a SRow structure 
	     */
	    aRow.ulAdrEntryPad = 0;
	    aRow.cValues = props_count;
	    aRow.lpProps = lpProps;

	    msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
	    if (msgid) {
		sizes[i - first] = *(const long *)
		    find_SPropValue_data(&aRow, PR_MESSAGE_SIZE);
	    }
	    talloc_free(lpProps);
	}
	mapi_object_release(&obj_message);
    }

    return PS_SUCCESS;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_getsizes
 *  Description:  capture the sizes of all messages
 * =====================================================================================
 */
static int
mapi_getsizes(int sock, int mail_count, int *sizes)
{
    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_getsizes(mail_count %d)\n", mail_count);

    /*-----------------------------------------------------------------------------
     *  set first to -1 to shut down report message in mapi_getpartialsizes()
     *-----------------------------------------------------------------------------*/
    return mapi_getpartialsizes(sock, -1, mail_count, sizes);
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_is_old
 *  Description:  is the given message old?
 * =====================================================================================
 */
static int
mapi_is_old(int sock, struct query *ctl, int number)
{
    enum MAPISTATUS retval;
    int             ok;
    int             flag = FALSE;
    struct SPropTagArray *SPropTagArray = NULL;
    struct SPropValue *lpProps;
    struct SRow     aRow;
    mapi_object_t   obj_message;
    const char     *msgid;
    mapi_id_t      *fid;
    mapi_id_t      *mid;
    int             props_count;

    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_is_old(number %d)\n", number);

    if (!mapi_initialized) {
	report(stderr, GT_("MAPI: MAPI is not initialized\n"));
	return (PS_UNDEFINED);
    }

    if (mapi_rowset.cRows < number)
	return FALSE;

    fid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[number - 1]), PR_FID);
    mid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[number - 1]), PR_MID);
    mapi_object_init(&obj_message);

    retval = OpenMessage(&mapi_obj_store, *fid, *mid, &obj_message, 0x0);
    if (retval == MAPI_E_SUCCESS) {
	SPropTagArray = set_SPropTagArray(mapi_mem_ctx, 0x1, PR_INTERNET_MESSAGE_ID);
	retval = GetProps(&obj_message, SPropTagArray, &lpProps, &props_count);
	MAPIFreeBuffer(SPropTagArray);
	if (retval == MAPI_E_SUCCESS) {
	    /*
	     * Build a SRow structure 
	     */
	    aRow.ulAdrEntryPad = 0;
	    aRow.cValues = props_count;
	    aRow.lpProps = lpProps;

	    msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
	    if (msgid) {
		retval = FindProfileAttr(mapi_profile, "Message-ID", msgid);
		if (retval == MAPI_E_SUCCESS) {
		    if (outlevel == O_DEBUG)
			report(stdout, "MAPI> message %d with Message-ID=%s is old\n", number, msgid);
		    flag = TRUE;
		}
	    }
	} else
	    mapi_clean();
	talloc_free(lpProps);
    }

    mapi_object_release(&obj_message);
    return flag;
}

static void
smtp_address(int *lenp, const char *name)
{
    struct SPropTagArray *SPropTagArray;
    struct SRowSet *SRowSet;
    enum MAPISTATUS retval;
    const char     *display_name = NULL;
    uint32_t        i;
    uint32_t        count;
    uint8_t         ulFlags;

    SPropTagArray = set_SPropTagArray(mapi_mem_ctx, 0x02, PR_DISPLAY_NAME_UNICODE, PR_SMTP_ADDRESS_UNICODE);

    count = 0x7;
    ulFlags = TABLE_START;
    do {
	count += 0x2;
	retval = GetGALTable(SPropTagArray, &SRowSet, count, ulFlags);
	if (retval != MAPI_E_SUCCESS) {
	    MapiWrite(lenp, "\n");
	    report(stderr, "MAPI: Error when translate display name into smtp address\n");
	    MAPIFreeBuffer(SRowSet);
	    MAPIFreeBuffer(SPropTagArray);
	    return;
	}
	if (SRowSet->cRows) {
	    for (i = 0; i < SRowSet->cRows; i++) {
		display_name = (const char *) find_SPropValue_data(&SRowSet->aRow[i], PR_DISPLAY_NAME_UNICODE);
		if (strcmp(display_name, name) == 0) {
		    MapiWrite(lenp, " <%s>\n", (const char *) find_SPropValue_data(&SRowSet->aRow[i], PR_SMTP_ADDRESS_UNICODE));
		    MAPIFreeBuffer(SRowSet);
		    MAPIFreeBuffer(SPropTagArray);
		    return;
		}
	    }
	}
	ulFlags = TABLE_CUR;
	MAPIFreeBuffer(SRowSet);
    } while (SRowSet->cRows == count);
    MAPIFreeBuffer(SPropTagArray);

    MapiWrite(lenp, "\n");
    return;
}
/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_fetch_headers
 *  Description:  request headers of the nth message
 *                set mapi_current_number to number, other work is done by readheaders()
 *                in transact.c
 * =====================================================================================
 */
static int
mapi_fetch_headers(int sock, struct query *ctl, int number, int *lenp)
{
    int             ok = PS_SUCCESS;
    enum MAPISTATUS retval;
    struct SPropTagArray *SPropTagArray = NULL;
    struct SPropValue *lpProps;
    struct SRow     aRow;
    mapi_object_t   obj_message;
    const char     *msgid;
    mapi_id_t      *fid;
    mapi_id_t      *mid;
    const uint64_t *delivery_date;
    const char     *date = NULL;
    const char     *from = NULL;
    const char     *to = NULL;
    const char     *cc = NULL;
    const char     *bcc = NULL;
    const char     *subject = NULL;
    const uint8_t  *has_attach = NULL;
    uint8_t         format;
    int             props_count;

    (void) ctl;
    *lenp = 0;

    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_fetch_headers(number %d)\n", number);

    if (!mapi_initialized) {
	report(stderr, GT_("MAPI: MAPI is not initialized\n"));
	return (PS_UNDEFINED);
    }

    if (mapi_rowset.cRows < number)
	return PS_UNDEFINED;

    fid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[number - 1]), PR_FID);
    mid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[number - 1]), PR_MID);
    mapi_object_init(&obj_message);

    retval = OpenMessage(&mapi_obj_store, *fid, *mid, &obj_message, 0x0);
    if (retval == MAPI_E_SUCCESS) {
	SPropTagArray = set_SPropTagArray(mapi_mem_ctx,
					  0x09,
					  PR_INTERNET_MESSAGE_ID,
					  PR_CONVERSATION_TOPIC,
					  PR_MESSAGE_DELIVERY_TIME,
					  PR_SENT_REPRESENTING_NAME,
					  PR_DISPLAY_TO, PR_DISPLAY_CC, PR_DISPLAY_BCC, PR_HASATTACH, PR_MSG_EDITOR_FORMAT);
	retval = GetProps(&obj_message, SPropTagArray, &lpProps, &props_count);
	MAPIFreeBuffer(SPropTagArray);
	if (retval != MAPI_E_SUCCESS) {
	    mapi_object_release(&obj_message);
	    return translate_mapi_error(GetLastError());
	}
    }
    /*
     * Build a SRow structure 
     */
    aRow.ulAdrEntryPad = 0;
    aRow.cValues = props_count;
    aRow.lpProps = lpProps;

    msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
    if (msgid) {
	has_attach = (const uint8_t *) octool_get_propval(&aRow, PR_HASATTACH);
	from = (const char *) octool_get_propval(&aRow, PR_SENT_REPRESENTING_NAME);
	to = (const char *) octool_get_propval(&aRow, PR_DISPLAY_TO);
	cc = (const char *) octool_get_propval(&aRow, PR_DISPLAY_CC);
	bcc = (const char *) octool_get_propval(&aRow, PR_DISPLAY_BCC);
	if (!to && !cc && !bcc) {
	    talloc_free(lpProps);
	    mapi_object_release(&obj_message);
	    return (PS_UNDEFINED);
	}

	delivery_date = (const uint64_t *) octool_get_propval(&aRow, PR_MESSAGE_DELIVERY_TIME);
	if (delivery_date) {
	    date = nt_time_string(mapi_mem_ctx, *delivery_date);
	} else {
	    date = "None";
	}
	subject = (const char *) octool_get_propval(&aRow, PR_CONVERSATION_TOPIC);

	/*
	 * initialize body DATA_BLOB 
	 */
	mapi_buffer.data = NULL;
	mapi_buffer.length = 0;
	mapi_buffer_count = 0;

	MapiWrite(lenp, "Date: %s\n", date);

	MapiWrite(lenp, "From: %s", from);
	smtp_address(lenp, from);

	if (to) {
	    MapiWrite(lenp, "To: %s", to);
	    smtp_address(lenp, to);
	}

	if (cc) {
	    MapiWrite(lenp, "Cc: %s", cc);
	    smtp_address(lenp, cc);
	}

	if (bcc) {
	    MapiWrite(lenp, "Bcc: %s", bcc);
	    smtp_address(lenp, bcc);
	}

	if (subject)
	    MapiWrite(lenp, "Subject: %s\n", subject);

	MapiWrite(lenp, "Message-ID: %s\n", msgid);
	MapiWrite(lenp, "MIME-Version: 1.0\n");

	if (has_attach && *has_attach) {
	    /*-----------------------------------------------------------------------------
	     * simple structure 
	     *-----------------------------------------------------------------------------*/
	    MapiWrite(lenp, "Content-Type: multipart/mixed; boundary=\"%s\"\n", MAPI_BOUNDARY);
	} else {
	    /*-----------------------------------------------------------------------------
	     * complex structure 
	     *-----------------------------------------------------------------------------*/
	    retval = GetBestBody(&obj_message, &format);
	    switch (format) {
	    case olEditorText:
		MapiWrite(lenp, "Content-Type: text/plain; charset=us-ascii\n");
		MapiWrite(lenp, "Content-Transfer-Encoding: quoted-printable\n");
		break;
	    case olEditorHTML:
		MapiWrite(lenp, "Content-Type: text/html\n");
		MapiWrite(lenp, "Content-Transfer-Encoding: quoted-printable\n");
		break;
	    case olEditorRTF:
		MapiWrite(lenp, "Content-Type: text/rtf\n");
		MapiWrite(lenp, "Content-Transfer-Encoding: quoted-printable\n");
		break;
	    }
	}
	MapiWrite(lenp, "\n");
    } else {
	talloc_free(lpProps);
	mapi_object_release(&obj_message);
	return (PS_UNDEFINED);
    }
    talloc_free(lpProps);
    mapi_object_release(&obj_message);

    return ok;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_fetch_body
 *  Description:  request body of nth message
 *                set mapi_current_number to number, other work is done by readbody()
 *                in transact.c
 * =====================================================================================
 */
static int
mapi_fetch_body(int sock, struct query *ctl, int number, int *lenp)
{
    int             ok = PS_SUCCESS;
    enum MAPISTATUS retval;
    struct SPropTagArray *SPropTagArray = NULL;
    struct SPropValue *lpProps;
    struct SRow     aRow;
    struct SRow     aRow2;
    struct SRowSet  rowset_attach;
    mapi_object_t   obj_message;
    mapi_object_t   obj_tb_attach;
    mapi_object_t   obj_attach;
    const char     *msgid;
    mapi_id_t      *fid;
    mapi_id_t      *mid;
    const uint8_t  *has_attach = NULL;
    const uint32_t *attach_num = NULL;
    DATA_BLOB       body;
    const char     *attach_filename;
    const uint32_t *attach_size;
    char           *attachment_data;
    char           *magic;
    int             props_count;
    int             attach_count;
    uint8_t         format;

    (void) ctl;
    *lenp = 0;

    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_fetch_body(number %d)\n", number);

    if (!mapi_initialized) {
	report(stderr, GT_("MAPI: MAPI is not initialized\n"));
	return (PS_UNDEFINED);
    }

    if (mapi_rowset.cRows < number)
	return (PS_UNDEFINED);

    fid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[number - 1]), PR_FID);
    mid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[number - 1]), PR_MID);
    mapi_object_init(&obj_message);

    retval = OpenMessage(&mapi_obj_store, *fid, *mid, &obj_message, 0x0);
    if (retval == MAPI_E_SUCCESS) {
	SPropTagArray = set_SPropTagArray(mapi_mem_ctx,
					  0x07,
					  PR_INTERNET_MESSAGE_ID,
					  PR_MSG_EDITOR_FORMAT,
					  PR_BODY, PR_BODY_UNICODE, PR_HTML, PR_RTF_COMPRESSED, PR_HASATTACH);
	retval = GetProps(&obj_message, SPropTagArray, &lpProps, &props_count);
	MAPIFreeBuffer(SPropTagArray);
	if (retval != MAPI_E_SUCCESS) {
	    mapi_object_release(&obj_message);
	    return translate_mapi_error(GetLastError());
	}
    }

    /*-----------------------------------------------------------------------------
     *  build a SRow structure
     *-----------------------------------------------------------------------------*/
    aRow.ulAdrEntryPad = 0;
    aRow.cValues = props_count;
    aRow.lpProps = lpProps;

    msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
    if (msgid) {
	has_attach = (const uint8_t *) find_SPropValue_data(&aRow, PR_HASATTACH);
	retval = octool_get_body(mapi_mem_ctx, &obj_message, &aRow, &body);

	/*-----------------------------------------------------------------------------
	 *  body
	 *-----------------------------------------------------------------------------*/
	if (body.length) {
	    if (has_attach && *has_attach) {
		MapiWrite(lenp, "--%s\n", MAPI_BOUNDARY);

		/*-----------------------------------------------------------------------------
		 *  complex structure
		 *-----------------------------------------------------------------------------*/
		retval = GetBestBody(&obj_message, &format);
		switch (format) {
		case olEditorText:
		    MapiWrite(lenp, "Content-Type: text/plain; charset=us-ascii\n");
		    MapiWrite(lenp, "Content-Transfer-Encoding: quoted-printable\n");
		    /*
		     * Just display UTF8 content inline 
		     */
		    MapiWrite(lenp, "Content-Disposition: inline\n");
		    break;
		case olEditorHTML:
		    MapiWrite(lenp, "Content-Type: text/html\n");
		    MapiWrite(lenp, "Content-Transfer-Encoding: quoted-printable\n");
		    break;
		case olEditorRTF:
		    MapiWrite(lenp, "Content-Type: text/rtf\n");
		    MapiWrite(lenp, "Content-Transfer-Encoding: quoted-printable\n");
		    MapiWrite(lenp, "--%s\n", MAPI_BOUNDARY);
		    break;
		}
	    }

	    /*-----------------------------------------------------------------------------
	     *  encode body.data into quoted printable and append to mapi_buffer
	     *-----------------------------------------------------------------------------*/
	    quoted_printable_encode(&body, lenp);
	    talloc_free(body.data);

	    /*-----------------------------------------------------------------------------
	     *  fetch attachments
	     *-----------------------------------------------------------------------------*/
	    if (has_attach && *has_attach) {
		mapi_object_init(&obj_tb_attach);
		retval = GetAttachmentTable(&obj_message, &obj_tb_attach);
		if (retval == MAPI_E_SUCCESS) {
		    SPropTagArray = set_SPropTagArray(mapi_mem_ctx, 0x1, PR_ATTACH_NUM);
		    retval = SetColumns(&obj_tb_attach, SPropTagArray);
		    MAPIFreeBuffer(SPropTagArray);
		    MAPI_RETVAL_IF(retval, retval, NULL);

		    retval = QueryRows(&obj_tb_attach, 0xa, TBL_ADVANCE, &rowset_attach);
		    MAPI_RETVAL_IF(retval, retval, NULL);

		    for (attach_count = 0; attach_count < rowset_attach.cRows; attach_count++) {
			attach_num =
			    (const uint32_t *) find_SPropValue_data(&(rowset_attach.aRow[attach_count]), PR_ATTACH_NUM);
			retval = OpenAttach(&obj_message, *attach_num, &obj_attach);
			if (retval == MAPI_E_SUCCESS) {
			    SPropTagArray = set_SPropTagArray(mapi_mem_ctx, 0x3,
							      PR_ATTACH_FILENAME, PR_ATTACH_LONG_FILENAME, PR_ATTACH_SIZE);
			    lpProps = talloc_zero(mapi_mem_ctx, struct SPropValue);
			    retval = GetProps(&obj_attach, SPropTagArray, &lpProps, &props_count);
			    MAPIFreeBuffer(SPropTagArray);
			    if (retval == MAPI_E_SUCCESS) {
				aRow2.ulAdrEntryPad = 0;
				aRow2.cValues = props_count;
				aRow2.lpProps = lpProps;

				attach_filename = get_filename(octool_get_propval(&aRow2, PR_ATTACH_LONG_FILENAME));
				if (!attach_filename || (attach_filename && !strcmp(attach_filename, ""))) {
				    attach_filename = get_filename(octool_get_propval(&aRow2, PR_ATTACH_FILENAME));
				}
				attach_size = (const uint32_t *) octool_get_propval(&aRow2, PR_ATTACH_SIZE);
				attachment_data = get_base64_attachment(mapi_mem_ctx, obj_attach, *attach_size, &magic);
				if (attachment_data) {
				    MapiWrite(lenp, "\n\n--%s\n", MAPI_BOUNDARY);
				    MapiWrite(lenp, "Content-Disposition: attachment; filename=\"%s\"\n", attach_filename);
				    MapiWrite(lenp, "Content-Type: \"%s\"\n", magic);
				    MapiWrite(lenp, "Content-Transfer-Encoding: base64\n\n");
				    data_blob_append(mapi_mem_ctx, &mapi_buffer, attachment_data, strlen(attachment_data));
				    *lenp += strlen(attachment_data);
				    talloc_free(attachment_data);
				}
			    }
			    MAPIFreeBuffer(lpProps);
			}
		    }
		    MapiWrite(lenp, "\n--%s--\n", MAPI_BOUNDARY);
		}		/* if GetAttachmentTable returns success */
	    }			/* if (has_attach && *has_attach) */
	}
	/*-----------------------------------------------------------------------------
	 *  send the message delimiter
	 *-----------------------------------------------------------------------------*/
	MapiWrite(lenp, "\n.\n\0", MAPI_BOUNDARY);
    } else {
	talloc_free(lpProps);
	mapi_object_release(&obj_message);
	return (PS_UNDEFINED);
    }
    mapi_object_release(&obj_message);

    return ok;
}

static int
mapi_trail(int sock, struct query *ctl, const char *tag)
{
    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_trail(tag %s)\n", tag);


    /*-----------------------------------------------------------------------------
     *  clear mapi buffer
     *-----------------------------------------------------------------------------*/
    talloc_free(mapi_buffer.data);
    mapi_buffer.data = NULL;
    mapi_buffer.length = 0;
    mapi_buffer_count = 0;

    return PS_SUCCESS;
}
/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_fetch_delete
 *  Description:  set delete flag for given message
 * =====================================================================================
 */ static int
mapi_delete(int sock, struct query *ctl, int number)
{
    mapi_container_list_t *element;

    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_delete(number %d)\n", number);

    if (!mapi_initialized)
	return (PS_UNDEFINED);

    if (mapi_rowset.cRows == 0)
	return PS_NOMAIL;

    element = talloc_zero((TALLOC_CTX *) mapi_deleted_ids.lpContainerList, mapi_container_list_t);
    element->id = mapi_rowset.aRow[number - 1].lpProps[1].value.d;;
    DLIST_ADD(mapi_deleted_ids.lpContainerList, element);
    mapi_deleted_ids.count++;
    return PS_SUCCESS;
}
/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_mark_seen
 *  Description:  make the given message as seen in both client and server sides
 * =====================================================================================
 */ static int
mapi_mark_seen(int sock, struct query *ctl, int number)
{
    enum MAPISTATUS retval;
    int             ok;
    int             flag = FALSE;
    struct SPropTagArray *SPropTagArray = NULL;
    struct SPropValue *lpProps;
    struct SRow     aRow;
    mapi_object_t   obj_message;
    const char     *msgid = NULL;
    const char     *profname = NULL;
    mapi_id_t      *fid;
    mapi_id_t      *mid;
    int             props_count;
    long            message_flags;

    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_mark_seen(number %d)\n", number);

    if (!mapi_initialized) {
	report(stderr, GT_("MAPI: MAPI is not initialized\n"));
	return (PS_UNDEFINED);
    }

    if (mapi_rowset.cRows < number)
	return FALSE;

    fid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[number - 1]), PR_FID);
    mid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[number - 1]), PR_MID);
    mapi_object_init(&obj_message);

    retval = OpenMessage(&mapi_obj_store, *fid, *mid, &obj_message, 0x0);
    if (retval == MAPI_E_SUCCESS) {
	SPropTagArray = set_SPropTagArray(mapi_mem_ctx, 0x2, PR_INTERNET_MESSAGE_ID, PR_MESSAGE_FLAGS);
	retval = GetProps(&obj_message, SPropTagArray, &lpProps, &props_count);
	MAPIFreeBuffer(SPropTagArray);
	if (retval == MAPI_E_SUCCESS) {
	    /*
	     * Build a SRow structure 
	     */
	    aRow.ulAdrEntryPad = 0;
	    aRow.cValues = props_count;
	    aRow.lpProps = lpProps;

	    msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
	    message_flags = *(const long *) find_SPropValue_data(&aRow, PR_MESSAGE_FLAGS);
	    if (msgid) {

		/*-----------------------------------------------------------------------------
		 * mark seen in the client side
		 *-----------------------------------------------------------------------------*/
		if (!ctl->mapi_profname)
		    profname = ctl->remotename;	/* use the remotename as the profile name */
		else
		    profname = ctl->mapi_profname;
		mapi_profile_add_string_attr(profname, "Message-ID", msgid);
		if (retval == MAPI_E_SUCCESS) {
		    if (outlevel == O_DEBUG)
			report(stdout, "MAPI> marked message %d with Message-ID=%s seen\n", number, msgid);
		    flag = TRUE;
		}

		/*-----------------------------------------------------------------------------
		 *  mark seen in the server side
		 *-----------------------------------------------------------------------------*/
		if (!(message_flags & MSGFLAG_READ)) {
		    retval = SetMessageReadFlag(&mapi_obj_inbox, &obj_message, MSGFLAG_READ);
		    if (retval != MAPI_E_SUCCESS) {
			// TODO: how to handle this?
		    }
		}
	    }
	} else
	    mapi_clean();
	talloc_free(lpProps);
    }
    mapi_object_release(&obj_message);

    return flag;
}



/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_end_mailbox_poll
 *  Description:  perform hard delete here
 * =====================================================================================
 */
static int
mapi_end_mailbox_poll(int sock, struct query *ctl)
{
    int             ok = PS_SUCCESS;
    (void) ctl;

    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_end_mailbox_poll()\n");

    ok = expunge_deleted();
    mapi_id_array_release(&mapi_deleted_ids);
    mapi_clean();
    mapi_initialized = FALSE;
    return ok;
}
static int
mapi_logout(int sock, struct query *ctl)
{
    int             ok = PS_SUCCESS;
    (void) ctl;

    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_logout()\n");

    return ok;
}
static const struct method mapi = {
    "MAPI",			/* Messaging Application Programming Interface */
    NULL,			/* unencrypted port, not used by MAPI */
    NULL,			/* SSL port, not used by MAPI */
    FALSE,			/* this is not a tagged protocol */
    TRUE,			/* since it's hard to calculate message size in MAPI, use a message delimiter */
    mapi_ok,			/* parse command response */
    mapi_getauth,		/* get authorization */
    mapi_getrange,		/* query range of messages */
    mapi_getsizes,		/* we can get a list of sizes */
    mapi_getpartialsizes,	/* we can get the size of 1 mail */
    mapi_is_old,		/* how do we tell a message is old? */
    mapi_fetch_headers,		/* request given message headers */
    mapi_fetch_body,		/* request given message body */
    mapi_trail,			/* eat message trailer */
    mapi_delete,		/* delete the message */
    mapi_mark_seen,		/* how to mark a message as seen */
    mapi_end_mailbox_poll,	/* end_of_mailbox processing */
    mapi_logout,		/* log out, we're done */
    TRUE,			/* yes, we can re-poll */
};


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  doMAPI
 *  Description:  retrieve messages using MAPI
 * =====================================================================================
 */
int
doMAPI(struct query *ctl)
{
    return (do_protocol(ctl, &mapi));
}
#endif				/* case MAPI_ENABLE */
/*
 * mapi.c ends here 
 */
