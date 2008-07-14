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

#define MAX_EMAIL	1024
#define DEFAULT_MAPI_PROFILES "%s/.fetchmail_mapi_profiles.ldb"

static TALLOC_CTX *mapi_mem_ctx;
static struct mapi_profile *mapi_profile;
static mapi_object_t mapi_obj_store;
static mapi_object_t mapi_obj_inbox;
static mapi_object_t mapi_obj_table;
static struct SRowSet mapi_rowset;
static int      mapi_initialized = FALSE;
/*
 * as said in fetchmail.h, these should be of size PATH_MAX 
 */
static char     mapi_profdb[1024];	/* mapi profiles databse */
static char     password[128];

static DATA_BLOB mapi_buffer;
static int      mapi_buffer_count;

 /*
  * :WORKAROUND:07/03/08 21:26:21:: Message numbers of deleted emails
  * Message numbers are used to keep track of emails in one session in
  * POP3 and IMAP, and this is handled in the server side. But there is no 
  * message number in MAPI, so the orders of emails appearing in the
  * mapi_obj_table are considered as their message number as a workaround. 
  */

/*-----------------------------------------------------------------------------
 *  entry[0] indicates how many entries are in the list
 *-----------------------------------------------------------------------------*/
#define MAPI_DELETED_LIST 1
#define MAPI_SEEN_LIST   2
static int      mapi_deleted_list[MAX_EMAIL + 1];
static int      mapi_seen_list[MAX_EMAIL + 1];


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
    int             bit_offset,
                    byte_offset,
                    idx,
                    i;
    const uint8_t  *d = (const uint8_t *) buf;
    int             bytes = (len * 8 + 5) / 6,
	pad_bytes = (bytes % 4) ? 4 - (bytes % 4) : 0;
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

    data.length = 0;
    data.data = talloc_size(mem_ctx, size);

    retval = OpenStream(&obj_attach, PR_ATTACH_DATA_BIN, 0, &obj_stream);
    if (retval != MAPI_E_SUCCESS)
	return false;

    if (size < MSGBUFSIZE) {
	retval = ReadStream(&obj_stream, buf, size, &read_size);
	if (retval != MAPI_E_SUCCESS)
	    return NULL;
	memcpy(data.data, buf, read_size);
    }

    for (stream_size = 0; stream_size < size; stream_size += MSGBUFSIZE) {
	retval = ReadStream(&obj_stream, buf, max_read_size, &read_size);
	if (retval != MAPI_E_SUCCESS)
	    return NULL;
	memcpy(data.data + stream_size, buf, read_size);
    }

    data.length = size;

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

static void
quoted_printable_encode(const DATA_BLOB * body)
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

	    line_count = 0;
	}
    }
    if (line_count != 0) {
	line[line_count++] = '\r';
	line[line_count] = '\n';
	data_blob_append(mapi_mem_ctx, &mapi_buffer, line, line_count);
    }
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  insert
 *  Description:  insert the number of an email to the given list
 * =====================================================================================
 */
static int
insert(int msg_num, int list)
{
    int            *p = NULL;
    int             idx;

    if (list == MAPI_DELETED_LIST)
	p = mapi_deleted_list;
    else
	p = mapi_seen_list;

    if (p[0] == MAX_EMAIL) {
	if (outlevel == O_DEBUG)
	    report(stderr, GT_("MAPI: can not handle more items in mapi_seen_list or mapi_deleted_list\n"));
	return FALSE;
    }

    for (idx = p[0]; idx >= 1; idx--) {
	if (p[idx] == msg_num)
	    return TRUE;
	if (p[idx] < msg_num)
	    break;
    }

    p[0]++;
    for (idx = p[0]; idx > 1; idx--) {
	if (p[idx - 1] > msg_num) {
	    p[idx] = p[idx - 1];
	} else
	    break;
    }
    p[idx] = msg_num;

    return TRUE;
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
    if (mapi_initialized)
	return ok;

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

    /*
     * Open Inbox 
     */

    /*-----------------------------------------------------------------------------
     *  Open folder
     *  TODO: open folder specified by --folder option
     *-----------------------------------------------------------------------------*/

    /*-----------------------------------------------------------------------------
     *  open inbox by default
     *-----------------------------------------------------------------------------*/
    retval = GetDefaultFolder(&mapi_obj_store, &id_folder, olFolderInbox);
    MAPI_RETVAL_IF(retval, retval, mapi_mem_ctx);

    mapi_object_init(&mapi_obj_inbox);
    retval = OpenFolder(&mapi_obj_store, id_folder, &mapi_obj_inbox);
    MAPI_RETVAL_IF(retval, retval, mapi_mem_ctx);

    mapi_object_init(&mapi_obj_table);
    retval = GetContentsTable(&mapi_obj_inbox, &mapi_obj_table, 0, &count);
    MAPI_RETVAL_IF(retval, retval, mapi_mem_ctx);

    SPropTagArray = set_SPropTagArray(mapi_mem_ctx, 0x2, PR_FID, PR_MID);
    retval = SetColumns(&mapi_obj_table, SPropTagArray);
    MAPIFreeBuffer(SPropTagArray);
    MAPI_RETVAL_IF(retval, retval, mapi_mem_ctx);

    retval = QueryRows(&mapi_obj_table, count, TBL_ADVANCE, &mapi_rowset);

    if (retval != MAPI_E_SUCCESS) {
	ok = GetLastError();
	mapi_clean();
	return ok;
    }

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
 *         Name:  expunge_seen
 *  Description:  set the MSGFLAG_READ property of the emails in the mapi_seen_list
 * =====================================================================================
 */
static int
expunge_seen()
{
    enum MAPISTATUS retval;
    struct SPropTagArray *SPropTagArray = NULL;
    struct SPropValue *lpProps;
    struct SRow     aRow;
    int             ok = PS_SUCCESS;
    const char     *msgid;
    mapi_object_t   obj_message;
    mapi_id_t      *fid;
    mapi_id_t      *mid;
    int             props_count;
    int             i;
    int             seen_idx;


    ok = mapi_init(NULL);
    if (ok)
	return translate_mapi_error(ok);

    if (mapi_rowset.cRows == 0)
	return PS_NOMAIL;

    for (i = 1; i < mapi_seen_list[0] && mapi_seen_list[i] <= mapi_rowset.cRows; i++) {
	seen_idx = mapi_seen_list[i];
	fid = (mapi_id_t *)
	    find_SPropValue_data(&(mapi_rowset.aRow[seen_idx - 1]), PR_FID);
	mid = (mapi_id_t *)
	    find_SPropValue_data(&(mapi_rowset.aRow[seen_idx - 1]), PR_MID);
	mapi_object_init(&obj_message);

	retval = OpenMessage(&mapi_obj_store, *fid, *mid, &obj_message, 0x0);

	if (retval == MAPI_E_SUCCESS) {
	    SPropTagArray = set_SPropTagArray(mapi_mem_ctx, 0x2, PR_INTERNET_MESSAGE_ID, PR_MESSAGE_FLAGS);
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
	    long            message_flags = *(const long *) find_SPropValue_data(&aRow,
										 PR_MESSAGE_FLAGS);
	    if (msgid && !(message_flags & MSGFLAG_READ)) {
		// mark this email as seen
		retval = SetMessageReadFlag(&mapi_obj_inbox, &obj_message, MSGFLAG_READ);
		if (retval != MAPI_E_SUCCESS) {
		    talloc_free(lpProps);
		    mapi_object_release(&obj_message);
		    return translate_mapi_error(GetLastError());
		}
	    }
	    talloc_free(lpProps);
	}
	mapi_object_release(&obj_message);
    }

    return PS_SUCCESS;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  expunge_deleted
 *  Description:  move the emails in the mapi_deleted_list into "deleted items" folder
 * =====================================================================================
 */
static int
expunge_deleted()
{
    enum MAPISTATUS retval;
    mapi_id_t       id_folder;
    struct SPropTagArray *SPropTagArray = NULL;
    struct SPropValue *lpProps;
    struct SRow     aRow;
    int             ok = PS_SUCCESS;
    const char     *msgid;
    mapi_object_t   obj_message;
    mapi_object_t   obj_deleted;
    mapi_id_array_t msg_id_array;
    mapi_id_t      *fid;
    mapi_id_t      *mid;
    int             props_count;
    int             i;
    int             deleted_idx;

    ok = mapi_init(NULL);
    if (ok)
	return translate_mapi_error(ok);

    if (mapi_rowset.cRows == 0)
	return PS_NOMAIL;

    mapi_id_array_init(&msg_id_array);
    for (i = 1; i <= mapi_deleted_list[0]
	 && mapi_deleted_list[i] <= mapi_rowset.cRows; i++) {
	deleted_idx = mapi_deleted_list[i];
	fid = (mapi_id_t *)
	    find_SPropValue_data(&(mapi_rowset.aRow[deleted_idx - 1]), PR_FID);
	mid = (mapi_id_t *)
	    find_SPropValue_data(&(mapi_rowset.aRow[deleted_idx - 1]), PR_MID);
	mapi_object_init(&obj_message);

	retval = OpenMessage(&mapi_obj_store, *fid, *mid, &obj_message, 0x0);
	if (retval == MAPI_E_SUCCESS) {
	    // move this email into "deleted items" folder
	    mapi_id_array_add_obj(&msg_id_array, &obj_message);
	    if (outlevel == O_DEBUG)
		report(stdout, "message in mapi_rowset.aRow[%d] will be moved to deleted items folder\n", deleted_idx - 1);
	}
	mapi_object_release(&obj_message);
    }

    mapi_object_init(&obj_deleted);
    retval = GetDefaultFolder(&mapi_obj_store, &id_folder, olFolderDeletedItems);
    retval = OpenFolder(&mapi_obj_store, id_folder, &obj_deleted);
    if (retval != MAPI_E_SUCCESS) {
	mapi_id_array_release(&msg_id_array);
	return translate_mapi_error(GetLastError());
    }

    retval = MoveCopyMessages(&mapi_obj_inbox, &obj_deleted, &msg_id_array, 0);
    if (retval != MAPI_E_SUCCESS && outlevel == O_DEBUG)
	mapi_errstr("MAPI> MoveCopyMessages", GetLastError());
    mapi_id_array_release(&msg_id_array);

    return translate_mapi_error(GetLastError());
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
	/*-----------------------------------------------------------------------------
	 *  initialize the lists
	 *-----------------------------------------------------------------------------*/
    memset(mapi_deleted_list, 0, sizeof(mapi_deleted_list));
    memset(mapi_seen_list, 0, sizeof(mapi_seen_list));


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


/*-----------------------------------------------------------------------------
 *  get range of messages to be fetched
 *-----------------------------------------------------------------------------*/
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

    ok = mapi_init(NULL);
    if (ok) {
	report(stderr, GT_("MAPI: MAPI initilize error in mapi_getrange\n"));
	return translate_mapi_error(ok);
    }

    *countp = mapi_rowset.cRows;

    if (mapi_rowset.cRows == 0)
	return PS_NOMAIL;

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

	    /*
	     * Build a SRow structure 
	     */
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
    int             i;

    if (first != -1) {
	if (outlevel >= O_MONITOR)
	    report(stdout, "MAPI> mapi_getpartialsizes(first %d, last %d)\n", first, last);
    } else
	first = 1;

    ok = mapi_init(NULL);
    if (ok) {
	report(stderr, GT_("MAPI: MAPI initilize error in mapi_getpartialsizes/mapi_getsizes\n"));
	return translate_mapi_error(ok);
    }

    if (mapi_rowset.cRows == 0)
	return PS_NOMAIL;

    mapi_id_t      *fid,
                   *mid;

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

    ok = mapi_init(NULL);
    if (ok) {
	report(stderr, GT_("MAPI: MAPI initilize error in mapi_is_old\n"));
	return FALSE;
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
    char           *temp_line;
    int             props_count;


    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_fetch_headers(number %d)\n", number);
    (void) ctl;
    ok = mapi_init(NULL);
    if (ok) {
	report(stderr, GT_("MAPI: MAPI initilize error in mapi_fetch_headers\n"));
	return translate_mapi_error(ok);
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
					  PR_MESSAGE_FLAGS,
					  PR_INTERNET_MESSAGE_ID,
					  PR_CONVERSATION_TOPIC,
					  PR_MESSAGE_DELIVERY_TIME,
					  PR_SENT_REPRESENTING_NAME,
					  PR_DISPLAY_TO, PR_DISPLAY_CC, PR_DISPLAY_BCC, PR_HASATTACH);
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

	temp_line = talloc_asprintf(mapi_mem_ctx, "From \"%s\" %s\n", from, date);
	data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
	talloc_free(temp_line);

	temp_line = talloc_asprintf(mapi_mem_ctx, "Date: %s\n", date);
	data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
	talloc_free(temp_line);

	temp_line = talloc_asprintf(mapi_mem_ctx, "From: %s\n", from);
	data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
	talloc_free(temp_line);

	if (to) {
	    temp_line = talloc_asprintf(mapi_mem_ctx, "To: %s\n", to);
	    data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
	    talloc_free(temp_line);
	}

	if (cc) {
	    temp_line = talloc_asprintf(mapi_mem_ctx, "Cc: %s\n", cc);
	    data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
	    talloc_free(temp_line);
	}

	if (bcc) {
	    temp_line = talloc_asprintf(mapi_mem_ctx, "Bcc: %s\n", bcc);
	    data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
	    talloc_free(temp_line);
	}

	if (subject) {
	    temp_line = talloc_asprintf(mapi_mem_ctx, "Subject: %s\n", subject);
	    data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
	    talloc_free(temp_line);
	}

	temp_line = talloc_asprintf(mapi_mem_ctx, "Message-ID: %s\n", msgid);
	data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
	talloc_free(temp_line);

	if (has_attach && *has_attach) {
	    temp_line = talloc_asprintf(mapi_mem_ctx, "Content-Type: multipart/mixed; boundary=\"%s\"\n", MAPI_BOUNDARY);
	    data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
	    talloc_free(temp_line);
	}

	temp_line = talloc_asprintf(mapi_mem_ctx, "\n");
	data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
	talloc_free(temp_line);
    } else {
	talloc_free(lpProps);
	mapi_object_release(&obj_message);
	return (PS_UNDEFINED);
    }
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
    char           *temp_line;
    int             props_count;
    int             attach_count;
    uint8_t         format;


    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_fetch_body(number %d)\n", number);

    (void) ctl;
    ok = mapi_init(NULL);
    if (ok) {
	report(stderr, GT_("MAPI: MAPI initilize error in mapi_fetch_body\n"));
	return translate_mapi_error(ok);
    }
    if (mapi_rowset.cRows < number)
	return (PS_UNDEFINED);

    talloc_free(mapi_buffer.data);
    mapi_buffer.data = NULL;
    mapi_buffer.length = 0;
    mapi_buffer_count = 0;

    fid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[number - 1]), PR_FID);
    mid = (mapi_id_t *) find_SPropValue_data(&(mapi_rowset.aRow[number - 1]), PR_MID);
    mapi_object_init(&obj_message);

    retval = OpenMessage(&mapi_obj_store, *fid, *mid, &obj_message, 0x0);
    if (retval == MAPI_E_SUCCESS) {
	SPropTagArray = set_SPropTagArray(mapi_mem_ctx,
					  0x08,
					  PR_MESSAGE_FLAGS,
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
    /*
     * Build a SRow structure 
     */
    aRow.ulAdrEntryPad = 0;
    aRow.cValues = props_count;
    aRow.lpProps = lpProps;

    msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
    if (msgid) {
	has_attach = (const uint8_t *) find_SPropValue_data(&aRow, PR_HASATTACH);
	retval = octool_get_body(mapi_mem_ctx, &obj_message, &aRow, &body);
	/*
	 * body 
	 */
	if (body.length) {
	    if (has_attach && *has_attach) {
		temp_line = talloc_asprintf(mapi_mem_ctx, "--%s\n", MAPI_BOUNDARY);
		data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
		talloc_free(temp_line);
	    }
	    retval = GetBestBody(&obj_message, &format);
	    switch (format) {
	    case olEditorText:
		temp_line = talloc_asprintf(mapi_mem_ctx, "Content-Type: text/plain; charset=us-ascii\n");
		data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
		talloc_free(temp_line);

		temp_line = talloc_asprintf(mapi_mem_ctx, "Content-Transfer-Encoding: quoted-printable\n");
		data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
		talloc_free(temp_line);
		/*
		 * Just display UTF8 content inline 
		 */
		temp_line = talloc_asprintf(mapi_mem_ctx, "Content-Disposition: inline\n");
		data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
		talloc_free(temp_line);
		break;
	    case olEditorHTML:
		temp_line = talloc_asprintf(mapi_mem_ctx, "Content-Type: text/html\n");
		data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
		talloc_free(temp_line);

		temp_line = talloc_asprintf(mapi_mem_ctx, "Content-Transfer-Encoding: quoted-printable\n");
		data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
		talloc_free(temp_line);
		break;
	    case olEditorRTF:
		temp_line = talloc_asprintf(mapi_mem_ctx, "Content-Type: text/rtf\n");
		data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
		talloc_free(temp_line);

		temp_line = talloc_asprintf(mapi_mem_ctx, "Content-Transfer-Encoding: quoted-printable\n");
		data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
		talloc_free(temp_line);

		temp_line = talloc_asprintf(mapi_mem_ctx, "--%s\n", MAPI_BOUNDARY);
		data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
		talloc_free(temp_line);
		break;
	    }

	    /*-----------------------------------------------------------------------------
	     *  encode body.data into quoted printable and append to mapi_buffer
	     *-----------------------------------------------------------------------------*/
	    quoted_printable_encode(&body);
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
				    temp_line = talloc_asprintf(mapi_mem_ctx, "\n\n--%s\n", MAPI_BOUNDARY);
				    data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
				    talloc_free(temp_line);

				    temp_line =
					talloc_asprintf(mapi_mem_ctx, "Content-Disposition: attachment; filename=\"%s\"\n",
							attach_filename);
				    data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
				    talloc_free(temp_line);

				    temp_line = talloc_asprintf(mapi_mem_ctx, "Content-Type: \"%s\"\n", magic);
				    data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
				    talloc_free(temp_line);

				    temp_line = talloc_asprintf(mapi_mem_ctx, "Content-Transfer-Encoding: base64\n\n");
				    data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
				    talloc_free(temp_line);

				    data_blob_append(mapi_mem_ctx, &mapi_buffer, attachment_data, strlen(attachment_data));
				    talloc_free(attachment_data);
				}
			    }
			    MAPIFreeBuffer(lpProps);
			}
		    }
		    if (has_attach && *has_attach) {
			temp_line = talloc_asprintf(mapi_mem_ctx, "\n--%s--\n", MAPI_BOUNDARY);
			data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
			talloc_free(temp_line);
		    }
		}

	    }


	    /*-----------------------------------------------------------------------------
	     *  send the message delimiter
	     *-----------------------------------------------------------------------------*/
	    temp_line = talloc_asprintf(mapi_mem_ctx, ".\n", MAPI_BOUNDARY);
	    data_blob_append(mapi_mem_ctx, &mapi_buffer, temp_line, strlen(temp_line));
	    talloc_free(temp_line);
	}
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
 */
static int
mapi_delete(int sock, struct query *ctl, int number)
{
    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_delete(number %d)\n", number);
    /*-----------------------------------------------------------------------------
     * perform a soft delete here
     * -----------------------------------------------------------------------------*/
    if (insert(number, MAPI_DELETED_LIST) == FALSE)
	return PS_UNDEFINED;
    return PS_SUCCESS;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_mark_seen
 *  Description:  make the given message as seen
 * =====================================================================================
 */
static int
mapi_mark_seen(int sock, struct query *ctl, int number)
{
    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_mark_seen(number %d)\n", number);
    /*-----------------------------------------------------------------------------
     *  perform a soft mark-seen here
     *-----------------------------------------------------------------------------*/
    if (insert(number, MAPI_SEEN_LIST))
	return PS_UNDEFINED;
    return PS_SUCCESS;
}



/*
 * ===  FUNCTION  ======================================================================
 *         Name:  mapi_end_mailbox_poll
 *  Description:  perform hard mark-seen and delete here
 * =====================================================================================
 */
static int
mapi_end_mailbox_poll(int sock, struct query *ctl)
{
    int             ok = PS_SUCCESS;
    (void) ctl;
    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_end_mailbox_poll()\n");


    if (mapi_seen_list[0]) {
	ok = expunge_seen();
	if (ok == PS_SUCCESS)
	    mapi_seen_list[0] = 0;
	else
	    return ok;
    }

    if (mapi_deleted_list[0]) {
	ok = expunge_deleted();
	if (ok == PS_SUCCESS)
	    mapi_deleted_list[0] = 0;
	else
	    return ok;
    }
    mapi_clean();
    mapi_initialized = FALSE;
    return ok;
}

static int
mapi_logout(int sock, struct query *ctl)
{
    int             ok = PS_SUCCESS;
    if (outlevel >= O_MONITOR)
	report(stdout, "MAPI> mapi_logout()\n");

    (void) ctl;
    if (mapi_seen_list[0]) {
	ok = expunge_seen();
	if (ok == PS_SUCCESS)
	    mapi_seen_list[0] = 0;
    }

    if (mapi_deleted_list[0]) {
	ok = expunge_deleted();
	if (ok == PS_SUCCESS)
	    mapi_deleted_list[0] = 0;
    }
    mapi_clean();
    mapi_initialized = FALSE;
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

int
doMAPI(struct query *ctl)
	/*
	 * retrieve messages using MAPI 
	 */
{
    return (do_protocol(ctl, &mapi));
}
#endif				/* case MAPI_ENABLE */

    /*
     * mapi.c ends here 
     */
