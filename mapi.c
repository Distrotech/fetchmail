/*
 *   mapi.c -- implement fetchmail's interface for new protocols in MAPI
 *
 *   Copyright (C) 2008 by Yangyan Li
 *   yangyan.li1986@gmail.com
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the
 *   Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include  "config.h"

#ifdef MAPI_ENABLE

#define USE_UINT_ENUMS 1
#include <libmapi/libmapi.h>
#include <ctype.h>

#if defined(HAVE_UNISTD_H)
# include <unistd.h>
#endif

#if defined(STDC_HEADERS)
# include <stdlib.h>
#endif

#include <errno.h>
#include <magic.h>

#include "fetchmail.h"
#include "gettext.h"
#include "openchange-tools.h"

/* samba includes */
#include <ldb.h>
#include <util/data_blob.h>

#define DEFAULT_MAPI_PROFILES "%s/.fetchmail_mapi_profiles.ldb"
#define MAPI_BOUNDARY "=_DocE+STaALJfprDB"

#ifndef PATH_MAX
# define PATH_MAX 1024
#endif

static TALLOC_CTX * g_mapi_mem_ctx;
static struct mapi_profile * mapi_profile;
static mapi_object_t g_mapi_obj_store;
static mapi_object_t g_mapi_obj_folder;
static mapi_object_t g_mapi_obj_table;
static mapi_id_array_t g_mapi_deleted_ids;
static struct SRowSet g_mapi_rowset;
static int g_mapi_initialized = FALSE;
static char g_mapi_profdb[PATH_MAX]; /* mapi profiles databse */
static char g_password[128];
static struct mapi_session * g_mapi_session = NULL;
static struct mapi_context *mapi_ctx;


static DATA_BLOB g_mapi_buffer;
static size_t g_mapi_buffer_count;



/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  MapiWrite
 *	Description:  write data into g_mapi_buffer
 * =====================================================================================
 */
void MapiWrite(int *lenp, const char *format, ...)
{

	va_list	ap;
	char * temp_line;
	va_start(ap, format);
	temp_line = talloc_vasprintf(g_mapi_mem_ctx, format, ap);
	data_blob_append(g_mapi_mem_ctx, &g_mapi_buffer, temp_line, strlen(temp_line));
	*lenp += strlen(temp_line);
	talloc_free(temp_line);
	va_end(ap);

	return;
}

/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  MapiRead
 *	Description:  match the interface of SockRead in socket.h to feed the driver with
 *				  MAPI data.
 * =====================================================================================
 */
int MapiRead (int sock, char *buf, int len)
{
	int count = 0;
	(void)sock;

	while (g_mapi_buffer_count < g_mapi_buffer.length) {
		*(buf + count) = *(g_mapi_buffer.data + g_mapi_buffer_count);
		count++;
		g_mapi_buffer_count++;
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
 * ===	FUNCTION  ======================================================================
 *		   Name:  MapiPeek
 *	Description:  match the interface of SockPeek.
 * =====================================================================================
 */
int MapiPeek (int sock)
{
	(void)sock;
	if (g_mapi_buffer_count < g_mapi_buffer.length)
		return *(g_mapi_buffer.data + g_mapi_buffer_count);
	else
		return -1;
}


static const char * get_filename (const char * filename)
{
	const char * substr = 0;

	if (!filename) return NULL;

	substr = rindex(filename, '/');
	if (substr) return substr;

	return filename;
}

/*
 * encode as base64
 * Samba4 code
 * caller frees
 */
static char * get_base64_attachment (TALLOC_CTX * mem_ctx, mapi_object_t obj_attach, const uint32_t size, char ** magic)
{
	mapi_object_t	obj_stream;
	DATA_BLOB	data;
	size_t		data_pos = 0;
	uint16_t	read_bytes = 0;
	magic_t		cookie = NULL;

	if (outlevel >= O_MONITOR) report(stdout, GT_("MAPI> mapi_get_base64_attachment(): size=%lu\n"), (const unsigned long)size);

	if (OpenStream(&obj_attach, PR_ATTACH_DATA_BIN, 0, &obj_stream) != MAPI_E_SUCCESS) return NULL;

	uint32_t data_length = 0;
	if (GetStreamSize(&obj_stream, &data_length) != MAPI_E_SUCCESS) return NULL;
	data.length = data_length;

	data.data = talloc_size(mem_ctx, data.length);
	if (outlevel >= O_MONITOR) report(stdout, GT_("MAPI> allocated size=%lu\n"), (unsigned long)data.length);

	do {
		if (ReadStream(&obj_stream, data.data + data_pos, MSGBUFSIZE, &read_bytes) != MAPI_E_SUCCESS) return NULL;
		data_pos += read_bytes;
	} while (data_pos < data.length);

	if (outlevel >= O_MONITOR) report(stdout, GT_("MAPI> All data received: data_pos=%lu\n"), (unsigned long)data_pos);

	cookie = magic_open(MAGIC_MIME);
	if (cookie == NULL) {
		report(stderr, GT_("MAPI> mime error: %s\n"), magic_error(cookie));
		return NULL;
	}
	if (magic_load(cookie, NULL) == -1) {
		report(stderr, GT_("MAPI> mime error: %s\n"), magic_error(cookie));
		magic_close(cookie);
		return NULL;
	}
	*magic = talloc_strdup(mem_ctx, magic_buffer(cookie, data.data, data.length));
	magic_close(cookie);

	return ldb_base64_encode(mem_ctx, (char const *)data.data, data.length);
}


/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  is_safe_char
 *	Description:  check if a character is safe to be represented as the ASCII character.
 * =====================================================================================
 */
static int is_safe_char(char ch)
{
	/*-----------------------------------------------------------------------------
	 *	For total robustness, it is better to quote every character except for the
	 *	73-character set known to be invariant across all gateways, that is the
	 *	letters anddigits (A-Z, a-z and 0-9) and the following 11 characters:
	 *	' ( ) + , - . / : = ?
	 *-----------------------------------------------------------------------------*/
	return isalnum(ch) || ch == '\'' || ch == '(' || ch == ')' || ch == '+' || ch == ','
		|| ch == '-' || ch == '.' || ch == '/' || ch == ':' || ch == '=' || ch == '?';
}


/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  quoted_printable_encode
 *	Description:  encode the body and append it to g_mapi_buffer
 * =====================================================================================
 */
static void quoted_printable_encode(const DATA_BLOB * body, int *lenp)
{
	int				line_count = 0;
	size_t			body_count = 0;
	char			hex[16] = "0123456789ABCDEF";
	char			ch;
	char			line[78];

	while (body_count < body->length)
	{
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

			data_blob_append(g_mapi_mem_ctx, &g_mapi_buffer, line, line_count);
			*lenp += line_count;

			line_count = 0;
		}
	}
	if (line_count != 0) {
		line[line_count++] = '\r';
		line[line_count] = '\n';
		data_blob_append(g_mapi_mem_ctx, &g_mapi_buffer, line, line_count);
		*lenp += line_count;
	}
}


static void mapi_clean()
{
	mapi_object_release(&g_mapi_obj_table);
	mapi_object_release(&g_mapi_obj_folder);
	mapi_object_release(&g_mapi_obj_store);
	MAPIUninitialize(mapi_ctx);
	talloc_free(g_mapi_mem_ctx);

	g_mapi_initialized = FALSE;
}


/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_open_folder
 *	Description:  open folder that matches the name specified by --folder option
 *				  Note: it only searches in the top level, i.e. it's not recursive
 * =====================================================================================
 */
static enum MAPISTATUS mapi_open_folder(mapi_object_t * obj_container, mapi_object_t * obj_child, const char *folder)
{
	enum MAPISTATUS retval;
	struct SPropTagArray * SPropTagArray;
	struct SPropValue * lpProps;
	struct SRowSet rowset;
	mapi_object_t obj_htable;
	char const * name = NULL;
	uint64_t const * fid = NULL;
	uint32_t idx = 0;
	uint32_t count = 0;

	mapi_object_init(&obj_htable);
	retval = GetHierarchyTable(obj_container, &obj_htable, 0, &count);
	if (retval != MAPI_E_SUCCESS) return GetLastError();

	SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx, 0x2, PR_DISPLAY_NAME, PR_FID);
	retval = SetColumns(&obj_htable, SPropTagArray);
	MAPIFreeBuffer(SPropTagArray);
	if (retval != MAPI_E_SUCCESS) return GetLastError();

	retval = QueryRows(&obj_htable, count, TBL_ADVANCE, &rowset);
	if (retval != MAPI_E_SUCCESS) return GetLastError();

	if (!rowset.cRows)
		return MAPI_E_NOT_FOUND;

	for (idx = 0; idx < rowset.cRows; idx++)
	{
		fid = (const uint64_t *) find_SPropValue_data(&rowset.aRow[idx], PR_FID);
		name = (const char *) find_SPropValue_data(&rowset.aRow[idx], PR_DISPLAY_NAME);

		if (fid && !strcmp(name, folder))
		{
			retval = OpenFolder(obj_container, *fid, obj_child);
			if (retval != MAPI_E_SUCCESS) break;

			/*-----------------------------------------------------------------------------
			 *	check the class of the folder, only IPF.Note and IPF.Post are supported
			 *-----------------------------------------------------------------------------*/
			SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx, 0x1, PR_CONTAINER_CLASS);
			retval = GetProps(obj_container, MAPI_UNICODE, SPropTagArray, &lpProps, &count);
			MAPIFreeBuffer(SPropTagArray);

			if ((lpProps[0].ulPropTag != PR_CONTAINER_CLASS) || (retval != MAPI_E_SUCCESS)) break;

			if (strcmp(lpProps[0].value.lpszA, "IPF.Note") == 0 || strcmp(lpProps[0].value.lpszA, "IPF.Post") == 0)
				return MAPI_E_SUCCESS;
		}
	}

	report(stderr, GT_("MAPI: No folder matches the one specified by --folder option\n"));
	return MAPI_E_NOT_FOUND;
}

static int mapi_init(const char *folder)
{
	enum MAPISTATUS retval;
	mapi_object_t	obj_tis;
	mapi_id_t	id_folder;
	struct SPropTagArray	*SPropTagArray = NULL;
	char			*profname = NULL;
	uint32_t		count;

	if (g_mapi_initialized) mapi_clean();

	g_mapi_mem_ctx = talloc_init("fetchmail");

	/*-----------------------------------------------------------------------------
	 *	Initialize MAPI subsystem
	 *-----------------------------------------------------------------------------*/
	retval = MAPIInitialize(&mapi_ctx, g_mapi_profdb);
	if (retval != MAPI_E_SUCCESS) {
		report(stderr, GT_("MAPI: MAPIInitialize failed\n"));
		mapi_clean();
		return GetLastError();
	}

	/*-----------------------------------------------------------------------------
	 *	use the default mapi_profile
	 *-----------------------------------------------------------------------------*/
	retval = GetDefaultProfile(mapi_ctx, &profname);
	if (retval != MAPI_E_SUCCESS) {
		report(stderr, GT_("MAPI: GetDefaultProfile failed\n"));
		mapi_clean();
		return GetLastError();
	}

	retval = MapiLogonEx(mapi_ctx, &g_mapi_session, profname, g_password);
	if (retval != MAPI_E_SUCCESS) {
		report(stderr, GT_("MAPI: MapiLogonEx failed\n"));
		mapi_clean();
		return GetLastError();
	}
	mapi_profile = g_mapi_session->profile;

	/*-----------------------------------------------------------------------------
	 *	Open the default message store
	 *-----------------------------------------------------------------------------*/
	mapi_object_init(&g_mapi_obj_store);
	retval = OpenMsgStore(g_mapi_session, &g_mapi_obj_store);
	if (retval != MAPI_E_SUCCESS) {
		report(stderr, GT_("MAPI: OpenMsgStore failed\n"));
		mapi_clean();
		return GetLastError();
	}

	if (folder != NULL)
	{
		/*-----------------------------------------------------------------------------
		 *	open TopInformationStore
		 *-----------------------------------------------------------------------------*/
		retval = GetDefaultFolder(&g_mapi_obj_store, &id_folder, olFolderTopInformationStore);
		if (retval != MAPI_E_SUCCESS) {
			report(stderr, GT_("MAPI: GetDefaultFolder-olFolderTopInformationStore failed\n"));
			mapi_clean();
			return GetLastError();
		}

		mapi_object_init(&obj_tis);
		retval = OpenFolder(&g_mapi_obj_store, id_folder, &obj_tis);
		if (retval != MAPI_E_SUCCESS) {
			report(stderr, GT_("MAPI: OpenFolder-olFolderTopInformationStore failed\n"));
			mapi_clean();
			return GetLastError();
		}

		retval = mapi_open_folder(&obj_tis, &g_mapi_obj_folder, folder);
		if (retval != MAPI_E_SUCCESS) {
			report(stderr, GT_("MAPI: mapi_open_folder failed\n"));
			mapi_clean();
			return retval;
		}
	}
	else
	{
		/*-----------------------------------------------------------------------------
		 *	open default Inbox
		 *-----------------------------------------------------------------------------*/
		retval = GetDefaultFolder(&g_mapi_obj_store, &id_folder, olFolderInbox);
		if (retval != MAPI_E_SUCCESS) {
			report(stderr, GT_("MAPI: GetDefaultFolder-olFolderInbox failed\n"));
			mapi_clean();
			return GetLastError();
		}

		mapi_object_init(&g_mapi_obj_folder);
		retval = OpenFolder(&g_mapi_obj_store, id_folder, &g_mapi_obj_folder);
		if (retval != MAPI_E_SUCCESS) {
			report(stderr, GT_("MAPI: OpenFolder failed\n"));
			mapi_clean();
			return GetLastError();
		}
	}

	mapi_object_init(&g_mapi_obj_table);
	retval = GetContentsTable(&g_mapi_obj_folder, &g_mapi_obj_table, 0, &count);
	if (retval != MAPI_E_SUCCESS) {
		report(stderr, GT_("MAPI: GetContentsTable failed\n"));
		mapi_clean();
		return GetLastError();
	}

	SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx, 0x2, PR_FID, PR_MID);
	retval = SetColumns(&g_mapi_obj_table, SPropTagArray);
	MAPIFreeBuffer(SPropTagArray);
	if (retval != MAPI_E_SUCCESS) {
		report(stderr, GT_("MAPI: SetColumns failed\n"));
		mapi_clean();
		return GetLastError();
	}

	retval = QueryRows(&g_mapi_obj_table, count, TBL_ADVANCE, &g_mapi_rowset);
	if (retval != MAPI_E_SUCCESS) {
		report(stderr, GT_("MAPI: QueryRows failed\n"));
		mapi_clean();
		return GetLastError();
	}

	mapi_id_array_init(mapi_ctx, &g_mapi_deleted_ids);
	g_mapi_initialized = TRUE;
	return MAPI_E_SUCCESS;
}

/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  translate_mapi_error
 *	Description:  translate mapi error code into fetchmail error code
 * =====================================================================================
 */
static int translate_mapi_error(enum MAPISTATUS mapi_error)
{
	switch (mapi_error) {
		case MAPI_E_SUCCESS: return PS_SUCCESS;
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

		default: return PS_UNDEFINED;
	}
}

/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  expunge_deleted
 *	Description:  perform hard delete
 * =====================================================================================
 */
static int expunge_deleted()
{
	enum MAPISTATUS retval;
	mapi_id_t	   *deleted_ids;

	if (g_mapi_deleted_ids.count == 0) return PS_SUCCESS;
	/*-----------------------------------------------------------------------------
	 *	perform hard delete
	 *-----------------------------------------------------------------------------*/
	mapi_id_array_get(g_mapi_mem_ctx, &g_mapi_deleted_ids, &deleted_ids);
	retval = DeleteMessage(&g_mapi_obj_folder, deleted_ids, g_mapi_deleted_ids.count);
	if (retval != MAPI_E_SUCCESS) {
		report(stderr, "MAPI: DeleteMessages failed\n");
		talloc_free(deleted_ids);
		return translate_mapi_error(GetLastError());
	}

	talloc_free(deleted_ids);
	return PS_SUCCESS;
}


/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_ok
 *	Description:  no need to parse response in MAPI, return PS_SUCCESS to fake the driver
 * =====================================================================================
 */
static int mapi_ok(int sock, char *argbuf)
{
	(void)sock;
	(void)argbuf;
	if (outlevel >= O_MONITOR) report(stdout, "MAPI> mapi_ok()\n");
	return PS_SUCCESS;
}


/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  callback
 *	Description:  when not running in daemon mode, give a chance to choose an account
 *				  while multiple accounts match the user name.
 *				  when running in daemon mode, skip this and mapi_getauth will return
 *				  PS_AUTHFAIL.
 * =====================================================================================
 */
static uint32_t callback(struct SRowSet *rowset, void *privat)
{
	/* TODO: check if running in daemon mode*/
	int				daemon_mode = FALSE;

	if (!daemon_mode)
	{
		uint32_t		i;
		struct SPropValue *lpProp;
		FILE		   *fd;
		uint32_t		idx;
		char			entry[10];
		const char	   *label = (const char *) privat;

		printf("%s:\n", label);
		for (i = 0; i < rowset->cRows; i++) {
			lpProp = get_SPropValue_SRow(&(rowset->aRow[i]), PR_DISPLAY_NAME);
			if (lpProp && lpProp->value.lpszA)
				printf("\t[%d] %s\n", i, lpProp->value.lpszA);
		}
		printf("\t[%d] cancel operation\n", i);
		fd = fdopen(0, "r");
		do {
			printf("Enter username id [0]: ");
			if(fgets(entry, 10, fd) == NULL)
				idx = 0;
			else
				idx = atoi(entry);
			if (idx > i) 
				printf("Invalid id - Valid range [0 - %d]\n", i);
		} while(idx > i);

		fclose(fd);
		return idx;
	}
	else
		return rowset->cRows;
}

/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_getauth
 *	Description:  1. synchronize mapi_profile with the setting
 *				  2. open the mapi_profile and initialize MAPI
 *				  if all of the operations are successful, it will be considered
 *				  a successful anthentication.
 * =====================================================================================
 */
static int mapi_getauth(int sock, struct query *ctl, char *greeting)
{
	enum MAPISTATUS retval;
	struct mapi_session *session = NULL;
	struct SRowSet	proftable;
	size_t profcount;
	char		localhost_name[256];
        const char      *ldif = NULL;
	const char	*profname = NULL;
	const char	*name_in_proftable = NULL;
	uint32_t	flags;
	const char	*locale = NULL;
	uint32_t	cpid = 0;
	uint32_t	lcid = 0;
	char		*cpid_str = NULL;
	char		*lcid_str = NULL;
	char		*realhost = ctl->server.via ? ctl->server.via : ctl->server.pollname;
	(void)sock;
	(void)greeting;

	if (outlevel > O_MONITOR) report(stdout, "MAPI> mapi_getauth()\n");

	g_mapi_mem_ctx = talloc_init("mapi_getauth");
	/*-----------------------------------------------------------------------------
	 *	initialize several options
	 *-----------------------------------------------------------------------------*/
	strcpy(g_password, ctl->password);

	ldif = talloc_strdup(g_mapi_mem_ctx, mapi_profile_get_ldif_path());
	profname = ctl->remotename;	/* use the remotename as the profile name */
	sprintf(g_mapi_profdb, DEFAULT_MAPI_PROFILES, getenv("HOME"));

	locale = (const char *) (ctl->mapi_language) ? mapi_get_locale_from_language(ctl->mapi_language) : mapi_get_system_locale();
	if (locale) {
		cpid = mapi_get_cpid_from_locale(locale);
		lcid = mapi_get_lcid_from_locale(locale);
	}

	/*-----------------------------------------------------------------------------
	 *	mapi_domain and mapi_realm are required option! how to check if it is specified?
	 *	if not specified, default values of ldif is used
	 *-----------------------------------------------------------------------------*/
	if (!ctl->mapi_domain || !ctl->mapi_realm || !ldif || !locale || !cpid || !lcid) {
		talloc_free(g_mapi_mem_ctx);
		return PS_AUTHFAIL;
	}

	if (access(g_mapi_profdb, F_OK) != 0) {
		/*-----------------------------------------------------------------------------
		 *	create mapi mapi_profile database
		 *-----------------------------------------------------------------------------*/
		retval = CreateProfileStore(g_mapi_profdb, ldif);
		if (retval != MAPI_E_SUCCESS) {
			talloc_free(g_mapi_mem_ctx);
			return translate_mapi_error(GetLastError());
		}
		if (outlevel == O_DEBUG) report(stdout, GT_("MAPI> MAPI mapi_profile database %s created\n"), g_mapi_profdb);
	}

	retval = MAPIInitialize(&mapi_ctx, g_mapi_profdb);
	if (retval != MAPI_E_SUCCESS) goto clean;
	if (outlevel == O_DEBUG) report(stdout, GT_("MAPI> MAPI initialized\n"));

	memset(&proftable, 0, sizeof(struct SRowSet));
	retval = GetProfileTable(mapi_ctx, &proftable);
	if (retval != MAPI_E_SUCCESS) goto clean;
	if (outlevel == O_DEBUG) report(stdout, GT_("MAPI> MAPI GetProfiletable\n"));

	for (profcount = 0; profcount != proftable.cRows; profcount++) {
		name_in_proftable = proftable.aRow[profcount].lpProps[0].value.lpszA;
		if (strcmp(name_in_proftable, profname) == 0) break;
	}

	if (profcount == proftable.cRows)
	{
		flags = 0;		/* do not save g_password in the mapi_profile */
		retval = CreateProfile(mapi_ctx, profname, ctl->remotename, g_password, flags);
		if (retval != MAPI_E_SUCCESS) goto clean;
	}

	mapi_profile_add_string_attr(mapi_ctx, profname, "binding", realhost);
	mapi_profile_add_string_attr(mapi_ctx, profname, "realm", ctl->mapi_realm);
	mapi_profile_add_string_attr(mapi_ctx, profname, "domain", ctl->mapi_domain);
        mapi_profile_add_string_attr(mapi_ctx, profname, "seal", "true");

	cpid_str = talloc_asprintf(g_mapi_mem_ctx, "%d", cpid);
	lcid_str = talloc_asprintf(g_mapi_mem_ctx, "%d", lcid);
	mapi_profile_add_string_attr(mapi_ctx, profname, "codepage", cpid_str);
	mapi_profile_add_string_attr(mapi_ctx, profname, "language", lcid_str);
	mapi_profile_add_string_attr(mapi_ctx, profname, "method", lcid_str);

	if (outlevel == O_DEBUG) report(stdout, GT_("MAPI> MAPI mapi_profile %s %s\n"), profname, (profcount==proftable.cRows)?"created":"updated");

	retval = MapiLogonProvider(mapi_ctx, &session, profname, g_password, PROVIDER_ID_NSPI);
	if (retval != MAPI_E_SUCCESS) goto clean;
	if (outlevel == O_DEBUG) report(stdout, GT_("MAPI> MapiLogonProvider\n"));

	retval = ProcessNetworkProfile(session, ctl->remotename, (mapi_profile_callback_t) callback, "Select a user id");
	if (retval != MAPI_E_SUCCESS) goto clean;
	if (outlevel == O_DEBUG) report(stdout, GT_("MAPI> processed a full and automated MAPI mapi_profile creation\n"));

	retval = SetDefaultProfile(mapi_ctx, profname);
	if (retval != MAPI_E_SUCCESS) goto clean;
	if (outlevel == O_DEBUG) report(stdout, GT_("MAPI> set default mapi_profile to %s\n"), profname);

	MAPIUninitialize(mapi_ctx);
	talloc_free(g_mapi_mem_ctx);
	return PS_SUCCESS;

clean:
	MAPIUninitialize(mapi_ctx);
	talloc_free(g_mapi_mem_ctx);
	return translate_mapi_error(GetLastError());
}


/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_getrange
 *	Description:  get range of messages to be fetched
 * =====================================================================================
 */
static int mapi_getrange(int sock, struct query *ctl, const char *folder, int *countp, int *newp, int *bytes)
{
	enum MAPISTATUS retval;
	int		status = PS_SUCCESS;
	struct SPropTagArray *SPropTagArray = NULL;
	struct SPropValue *lpProps;
	struct SRow		aRow;
	const char	   *msgid;
	uint32_t	props_count;
	mapi_object_t	obj_message;
	mapi_id_t const	* fid = 0;
	mapi_id_t const	* mid = 0;
	size_t i;

	(void)sock;
	(void)ctl;
	if (outlevel >= O_MONITOR) report(stdout, "MAPI> mapi_getrange()\n");

	*countp = 0;
	*newp = 0;
	*bytes = 0;


	/*-----------------------------------------------------------------------------
	 * initialize mapi here
	 *-----------------------------------------------------------------------------*/
	status = mapi_init(folder);
	if (status) {
		report(stderr, GT_("MAPI: MAPI is not initialized\n"));
		return PS_UNDEFINED;
	}

	*countp = g_mapi_rowset.cRows;

	for (i = 0; i < g_mapi_rowset.cRows; i++) {
		fid = find_SPropValue_data(&(g_mapi_rowset.aRow[i]), PR_FID);
		mid = find_SPropValue_data(&(g_mapi_rowset.aRow[i]), PR_MID);
		mapi_object_init(&obj_message);

		retval = OpenMessage(&g_mapi_obj_store, *fid, *mid, &obj_message, 0x0);

		if (retval == MAPI_E_SUCCESS)
		{
			long message_flags = 0;

			SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx, 0x3, PR_INTERNET_MESSAGE_ID, PR_MESSAGE_FLAGS, PR_MESSAGE_SIZE);
			retval = GetProps(&obj_message, MAPI_UNICODE, SPropTagArray, &lpProps, &props_count);
			MAPIFreeBuffer(SPropTagArray);
			if (retval != MAPI_E_SUCCESS) {
				status = translate_mapi_error(GetLastError());
				talloc_free(lpProps);
				mapi_object_release(&obj_message);
				mapi_clean();
				return status;
			}

			/*-----------------------------------------------------------------------------
			 *	build a SRow structure
			 *-----------------------------------------------------------------------------*/
			aRow.ulAdrEntryPad = 0;
			aRow.cValues = props_count;
			aRow.lpProps = lpProps;

			msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
			message_flags = *(const long *) find_SPropValue_data(&aRow, PR_MESSAGE_FLAGS);
			if (msgid && !(message_flags & MSGFLAG_READ))
			{
				(*newp)++;
				(*bytes) += *(const long *) find_SPropValue_data(&aRow, PR_MESSAGE_SIZE);
			}
			talloc_free(lpProps);
		}
		mapi_object_release(&obj_message);
	}

	return PS_SUCCESS;
}

/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_getpartialsizes
 *	Description:  capture the sizes of messages #first-#last
 * =====================================================================================
 */
static int mapi_getpartialsizes(int sock, int first, int last, int *sizes)
{
	enum MAPISTATUS retval;
	int				status = PS_SUCCESS;
	struct SPropTagArray *SPropTagArray = NULL;
	struct SPropValue *lpProps = NULL;
	struct SRow		aRow;
	uint32_t props_count = 0;
	mapi_object_t	obj_message;
	const char	   * msgid = NULL;
	mapi_id_t const	* fid = 0;
	mapi_id_t const	* mid = 0;
	int				i = 0;
	(void)sock;

	if (first != -1)
	{
		if (outlevel >= O_MONITOR) report(stdout, "MAPI> mapi_getpartialsizes(first %d, last %d)\n", first, last);
	}
	else
		first = 1;

	if (!g_mapi_initialized) {
		report(stderr, GT_("MAPI: MAPI is not initialized\n"));
		return PS_UNDEFINED;
	}

	for (i = first; i <= (int)g_mapi_rowset.cRows && i <= last; i++)
	{
		fid = find_SPropValue_data(&(g_mapi_rowset.aRow[i - 1]), PR_FID);
		mid = find_SPropValue_data(&(g_mapi_rowset.aRow[i - 1]), PR_MID);
		mapi_object_init(&obj_message);

		retval = OpenMessage(&g_mapi_obj_store, *fid, *mid, &obj_message, 0x0);

		if (retval == MAPI_E_SUCCESS)
		{
			SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx, 0x2, PR_INTERNET_MESSAGE_ID, PR_MESSAGE_SIZE);
			retval = GetProps(&obj_message, MAPI_UNICODE, SPropTagArray, &lpProps, &props_count);
			MAPIFreeBuffer(SPropTagArray);
			if (retval != MAPI_E_SUCCESS)
			{
				status = translate_mapi_error(GetLastError());
				talloc_free(lpProps);
				mapi_object_release(&obj_message);
				mapi_clean();
				return status;
			}

			/*
			 * Build a SRow structure
			 */
			aRow.ulAdrEntryPad = 0;
			aRow.cValues = props_count;
			aRow.lpProps = lpProps;

			msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
			if (msgid)
				sizes[i - first] = *(const long *) find_SPropValue_data(&aRow, PR_MESSAGE_SIZE);
			talloc_free(lpProps);
		}
		mapi_object_release(&obj_message);
	}

	return PS_SUCCESS;
}

/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_getsizes
 *	Description:  capture the sizes of all messages
 * =====================================================================================
 */
static int mapi_getsizes(int sock, int mail_count, int * sizes)
{
	if (outlevel >= O_MONITOR) report(stdout, "MAPI> mapi_getsizes(mail_count %d)\n", mail_count);

	/*-----------------------------------------------------------------------------
	 *	set first to -1 to shut down report message in mapi_getpartialsizes()
	 *-----------------------------------------------------------------------------*/
	return mapi_getpartialsizes(sock, -1, mail_count, sizes);
}

/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_is_old
 *	Description:  is the given message old?
 * =====================================================================================
 */
static int mapi_is_old(int sock, struct query *ctl, int number)
{
	enum MAPISTATUS retval;
	int				status = FALSE;
	struct SPropTagArray *SPropTagArray = NULL;
	struct SPropValue *lpProps;
	struct SRow		aRow;
	mapi_object_t	obj_message;
	const char	   *msgid;
	mapi_id_t const	* fid = 0;
	mapi_id_t const * mid = 0;
	uint32_t props_count;
	(void)sock;
	(void)ctl;

	if (outlevel >= O_MONITOR) report(stdout, "MAPI> mapi_is_old(number %d)\n", number);

	if (!g_mapi_initialized) {
		report(stderr, GT_("MAPI: MAPI is not initialized\n"));
		return PS_UNDEFINED;
	}

	if ((int)g_mapi_rowset.cRows < number) return FALSE;

	fid = find_SPropValue_data(&(g_mapi_rowset.aRow[number - 1]), PR_FID);
	mid = find_SPropValue_data(&(g_mapi_rowset.aRow[number - 1]), PR_MID);
	mapi_object_init(&obj_message);

	retval = OpenMessage(&g_mapi_obj_store, *fid, *mid, &obj_message, 0x0);
	if (retval == MAPI_E_SUCCESS)
	{
		SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx, 0x1, PR_INTERNET_MESSAGE_ID);
		retval = GetProps(&obj_message, MAPI_UNICODE, SPropTagArray, &lpProps, &props_count);
		MAPIFreeBuffer(SPropTagArray);
		if (retval == MAPI_E_SUCCESS) {
			/* Build a SRow structure */
			aRow.ulAdrEntryPad = 0;
			aRow.cValues = props_count;
			aRow.lpProps = lpProps;

			msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
			if (msgid) {
				retval = FindProfileAttr(mapi_profile, "Message-ID", msgid);
				if (retval == MAPI_E_SUCCESS) {
					if (outlevel == O_DEBUG) report(stdout, "MAPI> message %d with Message-ID=%s is old\n", number, msgid);
					status = TRUE;
				}
			}
		}
		else
			mapi_clean();
		talloc_free(lpProps);
	}

	mapi_object_release(&obj_message);
	return status;
}

/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  smtp_address
 *	Description:  write the smtp address which is crosponding to the given display name,
 *				  into g_mapi_buffer
 * =====================================================================================
 */
static void smtp_address(int *lenp, const char *name)
{
	struct SPropTagArray *SPropTagArray;
	struct SRowSet *SRowSet;
	enum MAPISTATUS retval;
	const char	   *display_name = NULL;
	uint32_t		i;
	uint32_t		count;
	uint8_t			ulFlags;

	SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx, 0x02, PR_DISPLAY_NAME_UNICODE, PR_SMTP_ADDRESS_UNICODE);
	count = 0x7;
	ulFlags = TABLE_START;
	do {
		count += 0x2;
		retval = GetGALTable(g_mapi_session, SPropTagArray, &SRowSet, count, ulFlags);
		if (retval != MAPI_E_SUCCESS)
		{
			MapiWrite(lenp, "\n");
			report(stderr, "MAPI: Error when translate display name into smtp address\n");
			MAPIFreeBuffer(SRowSet);
			MAPIFreeBuffer(SPropTagArray);
			return;
		}

		if (SRowSet->cRows)
		{
			for (i = 0; i < SRowSet->cRows; i++)
			{
				display_name = (const char *) find_SPropValue_data(&SRowSet->aRow[i], PR_DISPLAY_NAME_UNICODE);
				if (strcmp(display_name, name) == 0)
				{
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
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_fetch_headers
 *	Description:  request headers of the nth message, write message headers data into
 *				  g_mapi_buffer
 * =====================================================================================
 */
static int mapi_fetch_headers(int sock, struct query *ctl, int number, int *lenp)
{
	enum MAPISTATUS retval;
	struct SPropTagArray *SPropTagArray = NULL;
	struct SPropValue *lpProps = NULL;
	struct SRow		aRow;
	mapi_object_t	obj_message;
	const char	   * msgid = NULL;
	mapi_id_t const	   * fid = NULL;
	mapi_id_t const	   * mid = NULL;
	const uint64_t * delivery_date;
	const char	   * date = NULL;
	const char	   * from = NULL;
	const char	   * to = NULL;
	const char	   * cc = NULL;
	const char	   * bcc = NULL;
	const char	   * subject = NULL;
	const uint8_t  * has_attach = NULL;
	uint8_t	format = 0;
	uint32_t props_count = 0;

	(void) ctl;
	(void)sock;
	*lenp = 0;

	if (outlevel >= O_MONITOR) report(stdout, "MAPI> mapi_fetch_headers(number %d)\n", number);

	if (!g_mapi_initialized) {
		report(stderr, GT_("MAPI: MAPI is not initialized\n"));
		return (PS_UNDEFINED);
	}

	if ((int)g_mapi_rowset.cRows < number) return PS_UNDEFINED;

	fid = find_SPropValue_data(&(g_mapi_rowset.aRow[number - 1]), PR_FID);
	mid = find_SPropValue_data(&(g_mapi_rowset.aRow[number - 1]), PR_MID);
	mapi_object_init(&obj_message);

	retval = OpenMessage(&g_mapi_obj_store, *fid, *mid, &obj_message, 0x0);
	if (retval == MAPI_E_SUCCESS) {
		SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx,
						  0x09,
						  PR_INTERNET_MESSAGE_ID,
						  PR_CONVERSATION_TOPIC,
						  PR_MESSAGE_DELIVERY_TIME,
						  PR_SENT_REPRESENTING_NAME,
						  PR_DISPLAY_TO, PR_DISPLAY_CC, PR_DISPLAY_BCC, PR_HASATTACH, PR_MSG_EDITOR_FORMAT);
		retval = GetProps(&obj_message, MAPI_UNICODE, SPropTagArray, &lpProps, &props_count);
		MAPIFreeBuffer(SPropTagArray);
		if (retval != MAPI_E_SUCCESS) {
			mapi_object_release(&obj_message);
			return translate_mapi_error(GetLastError());
		}
	}

	/* Build a SRow structure */
	aRow.ulAdrEntryPad = 0;
	aRow.cValues = props_count;
	aRow.lpProps = lpProps;

	msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
	if (msgid)
	{
		has_attach = (const uint8_t *) octool_get_propval(&aRow, PR_HASATTACH);
		from = (const char *) octool_get_propval(&aRow, PR_SENT_REPRESENTING_NAME);
		to = (const char *) octool_get_propval(&aRow, PR_DISPLAY_TO);
		cc = (const char *) octool_get_propval(&aRow, PR_DISPLAY_CC);
		bcc = (const char *) octool_get_propval(&aRow, PR_DISPLAY_BCC);

		/*-----------------------------------------------------------------------------
		 * octool_get_propval() will not return NULL even if PR_DISPLAY_TO,
		 * PR_DISPLAY_CC or PR_DISPLAY_TO is null, so have a test on their lengths.
		 *-----------------------------------------------------------------------------*/
		if (strlen(to) * strlen(cc) * strlen(bcc)) {
			talloc_free(lpProps);
			mapi_object_release(&obj_message);
			return (PS_UNDEFINED);
		}

		delivery_date = (const uint64_t *) octool_get_propval(&aRow, PR_MESSAGE_DELIVERY_TIME);
		if (delivery_date) date = nt_time_string(g_mapi_mem_ctx, *delivery_date);
		else date = "None";

		subject = (const char *) octool_get_propval(&aRow, PR_CONVERSATION_TOPIC);

		/* initialize body DATA_BLOB */
		g_mapi_buffer.data = NULL;
		g_mapi_buffer.length = 0;
		g_mapi_buffer_count = 0;

		MapiWrite(lenp, "Date: %s\n", date);
		MapiWrite(lenp, "From: %s", from);
		smtp_address(lenp, from ? from : "<empty>");

		if (strlen(to)) {
			MapiWrite(lenp, "To: %s", to);
			smtp_address(lenp, to);
		}

		if (strlen(cc)) {
			MapiWrite(lenp, "Cc: %s", cc);
			smtp_address(lenp, cc ? cc : "<empty>");
		}

		if (strlen(bcc)) {
			MapiWrite(lenp, "Bcc: %s", bcc);
			smtp_address(lenp, bcc);
		}

		if (subject) MapiWrite(lenp, "Subject: %s\n", subject);

		MapiWrite(lenp, "Message-ID: %s\n", msgid);
		MapiWrite(lenp, "MIME-Version: 1.0\n");

		if (has_attach && *has_attach)
		{
			/*-----------------------------------------------------------------------------
			 * simple structure
			 *-----------------------------------------------------------------------------*/
			MapiWrite(lenp, "Content-Type: multipart/mixed; boundary=\"%s\"\n", MAPI_BOUNDARY);
		}
		else
		{
			/*-----------------------------------------------------------------------------
			 * complex structure
			 *-----------------------------------------------------------------------------*/
			retval = GetBestBody(&obj_message, &format);
			switch (format)
			{
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

	}
	else
	{
		talloc_free(lpProps);
		mapi_object_release(&obj_message);
		return PS_UNDEFINED;
	}
	talloc_free(lpProps);
	mapi_object_release(&obj_message);

	return PS_SUCCESS;
}


/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_fetch_body
 *	Description:  request body of nth message, write message body data into g_mapi_buffer
 * =====================================================================================
 */
static int mapi_fetch_body(int sock, struct query *ctl, int number, int *lenp)
{
	enum MAPISTATUS retval;
	struct SPropTagArray *SPropTagArray = NULL;
	struct SPropValue *lpProps = NULL;
	struct SPropValue *attach_lpProps = NULL;
	struct SRow		aRow;
	struct SRow		aRow2;
	struct SRowSet	rowset_attach;
	mapi_object_t	obj_message;
	mapi_object_t	obj_tb_attach;
	mapi_object_t	obj_attach;
	const char	   *msgid;
	mapi_id_t const	   *fid = NULL;
	mapi_id_t const	   *mid = NULL;
	const uint8_t  *has_attach = NULL;
	const uint32_t *attach_num = NULL;
	DATA_BLOB		body;
	const char	   *attach_filename;
	const uint32_t *attach_size;
	char		   *attachment_data;
	char		   *magic;
	uint32_t props_count = 0;
	uint32_t attach_count = 0;
	uint8_t format = 0;

	(void) ctl;
	(void)sock;
	*lenp = 0;

	if (outlevel >= O_MONITOR) report(stdout, "MAPI> mapi_fetch_body(number %d)\n", number);

	if (!g_mapi_initialized) {
		report(stderr, GT_("MAPI: MAPI is not initialized\n"));
		return (PS_UNDEFINED);
	}

	if ((int)g_mapi_rowset.cRows < number) return (PS_UNDEFINED);

	fid = find_SPropValue_data(&(g_mapi_rowset.aRow[number - 1]), PR_FID);
	mid = find_SPropValue_data(&(g_mapi_rowset.aRow[number - 1]), PR_MID);
	mapi_object_init(&obj_message);

	retval = OpenMessage(&g_mapi_obj_store, *fid, *mid, &obj_message, 0x0);
	if (retval != MAPI_E_SUCCESS) {
		mapi_object_release(&obj_message);
		return translate_mapi_error(GetLastError());
	}
	SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx,
					  0x07,
					  PR_INTERNET_MESSAGE_ID,
					  PR_MSG_EDITOR_FORMAT,
					  PR_BODY, PR_BODY_UNICODE, PR_HTML, PR_RTF_COMPRESSED, PR_HASATTACH);
	retval = GetProps(&obj_message, MAPI_UNICODE, SPropTagArray, &lpProps, &props_count);
	MAPIFreeBuffer(SPropTagArray);
	if (retval != MAPI_E_SUCCESS) {
		mapi_object_release(&obj_message);
		return translate_mapi_error(GetLastError());
	}

	/*-----------------------------------------------------------------------------
	 *	build a SRow structure
	 *-----------------------------------------------------------------------------*/
	aRow.ulAdrEntryPad = 0;
	aRow.cValues = props_count;
	aRow.lpProps = lpProps;

	msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
	if (!msgid) {
		talloc_free(lpProps);
		mapi_object_release(&obj_message);
		return (PS_UNDEFINED);
	}

	has_attach = (const uint8_t *) find_SPropValue_data(&aRow, PR_HASATTACH);
	retval = octool_get_body(g_mapi_mem_ctx, &obj_message, &aRow, &body);

	/*-----------------------------------------------------------------------------
	 *	body
	 *-----------------------------------------------------------------------------*/
	if (body.length)
	{
		if (has_attach && *has_attach)
		{
			MapiWrite(lenp, "--%s\n", MAPI_BOUNDARY);

			/*-----------------------------------------------------------------------------
			 *	complex structure
			 *-----------------------------------------------------------------------------*/
			retval = GetBestBody(&obj_message, &format);
			switch (format) {
				case olEditorText:
					MapiWrite(lenp, "Content-Type: text/plain; charset=us-ascii\n");
					MapiWrite(lenp, "Content-Transfer-Encoding: quoted-printable\n");
					/* Just display UTF8 content inline */
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
		 *	encode body.data into quoted printable and append to g_mapi_buffer
		 *-----------------------------------------------------------------------------*/
		quoted_printable_encode(&body, lenp);
		talloc_free(body.data);

		/*-----------------------------------------------------------------------------
		 *	fetch attachments
		 *-----------------------------------------------------------------------------*/
		if (has_attach && *has_attach) {
			mapi_object_init(&obj_tb_attach);
			retval = GetAttachmentTable(&obj_message, &obj_tb_attach);
			if (retval == MAPI_E_SUCCESS) {
				SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx, 0x1, PR_ATTACH_NUM);
				retval = SetColumns(&obj_tb_attach, SPropTagArray);
				MAPIFreeBuffer(SPropTagArray);
				if (retval != MAPI_E_SUCCESS) {
					mapi_object_release(&obj_message);
					return translate_mapi_error(GetLastError());
				}

				retval = QueryRows(&obj_tb_attach, 0xa, TBL_ADVANCE, &rowset_attach);
				if (retval != MAPI_E_SUCCESS) {
					mapi_object_release(&obj_message);
					return translate_mapi_error(GetLastError());
				}

				for (attach_count = 0; attach_count < rowset_attach.cRows; attach_count++)
				{
					attach_num = (const uint32_t *) find_SPropValue_data(&(rowset_attach.aRow[attach_count]), PR_ATTACH_NUM);
					retval = OpenAttach(&obj_message, *attach_num, &obj_attach);
					if (retval == MAPI_E_SUCCESS)
					{
						SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx, 0x3,
										  PR_ATTACH_FILENAME, PR_ATTACH_LONG_FILENAME, PR_ATTACH_SIZE);
						retval = GetProps(&obj_attach, MAPI_UNICODE, SPropTagArray, &attach_lpProps, &props_count);
						MAPIFreeBuffer(SPropTagArray);
						if (retval == MAPI_E_SUCCESS) {
							aRow2.ulAdrEntryPad = 0;
							aRow2.cValues = props_count;
							aRow2.lpProps = attach_lpProps;

							attach_filename = get_filename(octool_get_propval(&aRow2, PR_ATTACH_LONG_FILENAME));
							if (!attach_filename || (attach_filename && !strcmp(attach_filename, "")))
								attach_filename = get_filename(octool_get_propval(&aRow2, PR_ATTACH_FILENAME));
							attach_size = (const uint32_t *) octool_get_propval(&aRow2, PR_ATTACH_SIZE);
							attachment_data = get_base64_attachment(g_mapi_mem_ctx, obj_attach, *attach_size, &magic);
							if (attachment_data)
							{
								MapiWrite(lenp, "\n\n--%s\n", MAPI_BOUNDARY);
								MapiWrite(lenp, "Content-Disposition: attachment; filename=\"%s\"\n", attach_filename);
								MapiWrite(lenp, "Content-Type: \"%s\"\n", magic);
								MapiWrite(lenp, "Content-Transfer-Encoding: base64\n\n");
								data_blob_append(g_mapi_mem_ctx, &g_mapi_buffer, attachment_data, strlen(attachment_data));
								*lenp += strlen(attachment_data);
								talloc_free(attachment_data);
							}
						}
						talloc_free(attach_lpProps);
					}
				}
				MapiWrite(lenp, "\n--%s--\n", MAPI_BOUNDARY);
			}			/* if GetAttachmentTable returns success */
		}			/* if (has_attach && *has_attach) */
	}
	/*-----------------------------------------------------------------------------
	 *	send the message delimiter
	 *-----------------------------------------------------------------------------*/
	MapiWrite(lenp, "\n.\n\0");

	talloc_free(lpProps);
	mapi_object_release(&obj_message);

	return (PS_SUCCESS);
}

/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_tail
 *	Description:  will be invoked after mapi_fetch_body and mapi_fetch_headers to clear
 *				  g_mapi_buffer.
 * =====================================================================================
 */
static int mapi_trail(int sock, struct query *ctl, const char * tag)
{
	(void)ctl;
	(void)sock;
	if (outlevel >= O_MONITOR) report(stdout, "MAPI> mapi_trail(tag %s)\n", tag);

	/*-----------------------------------------------------------------------------
	 *	clear mapi buffer
	 *-----------------------------------------------------------------------------*/
	talloc_free(g_mapi_buffer.data);
	g_mapi_buffer.data = NULL;
	g_mapi_buffer.length = 0;
	g_mapi_buffer_count = 0;

	return PS_SUCCESS;
}
/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_fetch_delete
 *	Description:  set delete flag for given message
 * =====================================================================================
 */
static int mapi_delete(int sock, struct query *ctl, int number)
{
	mapi_container_list_t *element;
	enum MAPISTATUS retval;
	const char	   *profname = NULL;
	int				status = PS_UNDEFINED;
	struct SPropTagArray *SPropTagArray = NULL;
	struct SPropValue *lpProps;
	struct SRow		aRow;
	mapi_object_t	obj_message;
	const char	   *msgid;
	mapi_id_t const	   *fid = 0;
	mapi_id_t const	   *mid = 0;
	uint32_t props_count = 0;

	(void)sock;

	if (outlevel >= O_MONITOR) report(stdout, "MAPI> mapi_delete(number %d)\n", number);

	if (!g_mapi_initialized) return PS_UNDEFINED;
	if (g_mapi_rowset.cRows == 0) return PS_NOMAIL;

	element = talloc_zero((TALLOC_CTX *) g_mapi_deleted_ids.lpContainerList, mapi_container_list_t);
	element->id = g_mapi_rowset.aRow[number - 1].lpProps[1].value.d;
	DLIST_ADD(g_mapi_deleted_ids.lpContainerList, element);
	g_mapi_deleted_ids.count++;

	/*-----------------------------------------------------------------------------
	 *	remove id in the profile
	 *-----------------------------------------------------------------------------*/
	profname = ctl->remotename;	/* use the remotename as the profile name */

	fid = find_SPropValue_data(&(g_mapi_rowset.aRow[number - 1]), PR_FID);
	mid = find_SPropValue_data(&(g_mapi_rowset.aRow[number - 1]), PR_MID);
	mapi_object_init(&obj_message);

	retval = OpenMessage(&g_mapi_obj_store, *fid, *mid, &obj_message, 0x0);
	if (retval == MAPI_E_SUCCESS)
	{
		SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx, 0x1, PR_INTERNET_MESSAGE_ID);
		retval = GetProps(&obj_message, MAPI_UNICODE, SPropTagArray, &lpProps, &props_count);
		MAPIFreeBuffer(SPropTagArray);
		if (retval == MAPI_E_SUCCESS)
		{
			/* Build a SRow structure */
			aRow.ulAdrEntryPad = 0;
			aRow.cValues = props_count;
			aRow.lpProps = lpProps;

			msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
			if (msgid) {
				retval = mapi_profile_delete_string_attr(mapi_ctx, profname, "Message-ID", msgid);
				if (retval == MAPI_E_SUCCESS) {
					if (outlevel == O_DEBUG) report(stdout, "MAPI> message %d with Message-ID=%s will be deleted\n", number, msgid);
					status = PS_SUCCESS;
				}
			}
		}
		else mapi_clean();
		talloc_free(lpProps);
	}

	mapi_object_release(&obj_message);
	return status;
}


/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_mark_seen
 *	Description:  make the given message as seen in both client and server sides
 * =====================================================================================
 */
static int mapi_mark_seen(int sock, struct query *ctl, int number)
{
	enum MAPISTATUS retval;
	int				status = FALSE; /* TODO: weird mixing of PS_* and TRUE/FALSE */
	struct SPropTagArray *SPropTagArray = NULL;
	struct SPropValue *lpProps;
	struct SRow		aRow;
	mapi_object_t	obj_message;
	const char	   *msgid = NULL;
	const char	   *profname = NULL;
	mapi_id_t const	* fid = 0;
	mapi_id_t const	* mid = 0;
	uint32_t props_count = 0;
	long			message_flags;
	(void)sock;

	if (outlevel >= O_MONITOR) report(stdout, "MAPI> mapi_mark_seen(number %d)\n", number);

	if (!g_mapi_initialized) {
		report(stderr, GT_("MAPI: MAPI is not initialized\n"));
		return PS_UNDEFINED;
	}

	if ((int)g_mapi_rowset.cRows < number) return FALSE;

	fid = find_SPropValue_data(&(g_mapi_rowset.aRow[number - 1]), PR_FID);
	mid = find_SPropValue_data(&(g_mapi_rowset.aRow[number - 1]), PR_MID);
	mapi_object_init(&obj_message);

	retval = OpenMessage(&g_mapi_obj_store, *fid, *mid, &obj_message, 0x0);
	if (retval == MAPI_E_SUCCESS) {
		SPropTagArray = set_SPropTagArray(g_mapi_mem_ctx, 0x2, PR_INTERNET_MESSAGE_ID, PR_MESSAGE_FLAGS);
		retval = GetProps(&obj_message, MAPI_UNICODE, SPropTagArray, &lpProps, &props_count);
		MAPIFreeBuffer(SPropTagArray);
		if (retval == MAPI_E_SUCCESS)
		{
			/* Build a SRow structure */
			aRow.ulAdrEntryPad = 0;
			aRow.cValues = props_count;
			aRow.lpProps = lpProps;

			msgid = (const char *) find_SPropValue_data(&aRow, PR_INTERNET_MESSAGE_ID);
			message_flags = *(const long *) find_SPropValue_data(&aRow, PR_MESSAGE_FLAGS);
			if (msgid)
			{
				retval = FindProfileAttr(mapi_profile, "Message-ID", msgid);
				if (retval == MAPI_E_SUCCESS)
				{
					if (outlevel == O_DEBUG) report(stdout, "MAPI> message %d with Message-ID=%s is already marked as seen\n", number, msgid);
					status = TRUE;
					talloc_free(lpProps);
					mapi_object_release(&obj_message);
					return status;
				}

				/*-----------------------------------------------------------------------------
				 * mark seen in the client side
				 *-----------------------------------------------------------------------------*/
				profname = ctl->remotename;	/* use the remotename as the profile name */
				mapi_profile_add_string_attr(mapi_ctx, profname, "Message-ID", msgid);
				if (retval == MAPI_E_SUCCESS) {
					if (outlevel == O_DEBUG) report(stdout, "MAPI> marked message %d with Message-ID=%s seen\n", number, msgid);
					status = TRUE;
				}

				/*-----------------------------------------------------------------------------
				 *	mark seen in the server side
				 *-----------------------------------------------------------------------------*/
				if (!(message_flags & MSGFLAG_READ))
				{
					retval = SetMessageReadFlag(&g_mapi_obj_folder, &obj_message, MSGFLAG_READ);
					if (retval != MAPI_E_SUCCESS) {
						talloc_free(lpProps);
						mapi_object_release(&obj_message);
						return status;
					}
				}
			}
		}
		else mapi_clean();
		talloc_free(lpProps);
	}
	mapi_object_release(&obj_message);

	return status;
}


/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_end_mailbox_poll
 *	Description:  perform hard delete here
 * =====================================================================================
 */
static int mapi_end_mailbox_poll(int sock, struct query *ctl)
{
	int				status = PS_SUCCESS;
	(void)ctl;
	(void)sock;
	if (outlevel >= O_MONITOR) report(stdout, "MAPI> mapi_end_mailbox_poll()\n");

	status = expunge_deleted();
	mapi_id_array_release(&g_mapi_deleted_ids);
	mapi_clean();
	return status;
}


/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  mapi_logout
 *	Description:
 * =====================================================================================
 */
static int mapi_logout(int sock, struct query *ctl)
{
	(void)ctl;
	(void)sock;
	if (outlevel >= O_MONITOR) report(stdout, "MAPI> mapi_logout()\n");

	if (g_mapi_initialized) mapi_clean();
	return PS_SUCCESS;
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
	TRUE			/* yes, we can re-poll */
};


/*
 * ===	FUNCTION  ======================================================================
 *		   Name:  doMAPI
 *	Description:  retrieve messages using MAPI
 * =====================================================================================
 */
int doMAPI(struct query *ctl)
{
	return do_protocol(ctl, &mapi);
}
#endif				/* case MAPI_ENABLE */
/*
 * mapi.c ends here
 */
