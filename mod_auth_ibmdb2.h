/*
  +----------------------------------------------------------------------+
  | mod_auth_ibmdb2: structures, defines, globals                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 2004-2007 Helmut K. C. Tessarek                        |
  +----------------------------------------------------------------------+
  | Licensed under the Apache License, Version 2.0 (the "License"); you  |
  | may not use this file except in compliance with the License. You may |
  | obtain a copy of the License at                                      |
  | http://www.apache.org/licenses/LICENSE-2.0                           |
  |                                                                      |
  | Unless required by applicable law or agreed to in writing, software  |
  | distributed under the License is distributed on an "AS IS" BASIS,    |
  | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or      |
  | implied. See the License for the specific language governing         |
  | permissions and limitations under the License.                       |
  +----------------------------------------------------------------------+
  | Author: Helmut K. C. Tessarek                                        |
  +----------------------------------------------------------------------+
  | Website: http://mod-auth-ibmdb2.sourceforge.net                      |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef MOD_AUTH_IBMDB2_H
#define MOD_AUTH_IBMDB2_H

#ifndef FALSE								// FALSE
#define FALSE 0
#endif
#ifndef TRUE								// TRUE
#define TRUE (!FALSE)
#endif

#define MAX_IBMDB2_UID_LENGTH   18
#define MAX_IBMDB2_PWD_LENGTH   30
#define MAX_UID_LENGTH          32
#define MAX_PWD_LENGTH          64
#define MAX_GRP_LENGTH         128

#define LOG_DBG( msg ) ap_log_rerror( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r, "%s", msg )
#define LOG_DBGS( msg ) ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, s, "%s", msg )
#define LOG_ERROR( msg ) ap_log_rerror( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "%s", msg )
#define MAXERRLEN             1024


//	structure to hold the configuration details for the request
typedef struct  {
	char *ibmdb2user;						// user ID to connect to db server
	char *ibmdb2passwd;						// password to connect to db server
	char *ibmdb2DB;							// Database name
	char *ibmdb2pwtable;					// user password table
	char *ibmdb2grptable;					// user group table
	char *ibmdb2NameField;					// field in password/grp table with username
	char *ibmdb2PasswordField;				// field in password table with password
	char *ibmdb2GroupField;					// field in group table with group name
	int  ibmdb2Crypted;						// are passwords encrypted?
	int  ibmdb2KeepAlive;					// keep connection persistent?
	int  ibmdb2Authoritative;				// are we authoritative?
	int  ibmdb2NoPasswd;					// do we ignore password?
	char *ibmdb2UserCondition; 				// Condition to add to the user where-clause in select query
	char *ibmdb2GroupCondition;				// Condition to add to the group where-clause in select query
	char *ibmdb2UserProc;					// stored procedure for user auth
	char *ibmdb2GroupProc;					// stored procedure for group auth
	int  ibmdb2caching;						// are user credentials cached?
	int  ibmdb2grpcaching;					// is group information cached?
	char *ibmdb2cachefile;					// path to cache file
	char *ibmdb2cachelifetime;				// cache lifetime in seconds
} ibmdb2_auth_config_rec;

//	structure to hold the sqlca variables
typedef struct
{
	char msg[SQL_MAX_MESSAGE_LENGTH + 1];
	char state[SQL_SQLSTATE_SIZE + 1];
	int code;
} sqlerr_t;


static SQLHANDLE   henv;					// environment handle
static SQLHANDLE   hdbc;					// db connection handle

#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
