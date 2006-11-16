/*
  +----------------------------------------------------------------------+
  | mod_auth_ibmdb2: authentication using an IBM DB2 database            |
  +----------------------------------------------------------------------+
  | Copyright (c) 2004-2006 Helmut K. C. Tessarek                        |
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

/*
   Module definition information - the part between the -START and -END
   lines below is used by Configure. This could be stored in a separate
   instead.

   MODULE-DEFINITION-START
   Name: ibmdb2_auth_module
   ConfigStart
     IBMDB2_LIB="-L/opt/IBM/db2/V8.1/lib -L/home/db2inst1/sqllib/lib/"
     if [ "X$IBMDB2_LIB" != "X" ]; then
         DB2_LIBS="-ldb2 -lgdbm"
         LIBS="$LIBS $IBMDB2_LIB $DB2_LIBS"
         echo " + using $IBMDB2_LIB for IBM DB2 support"
     fi
     IBMDB2_INC="-I/opt/IBM/db2/V8.1/include -I/home/db2inst1/sqllib/include/"
     if [ "X$IBMDB2_INC" != "X" ]; then
         INCLUDES="$INCLUDES $IBMDB2_INC"
         echo " + using $IBMDB2_INC for IBM DB2 support"
     fi
     DB2_CFLAGS="-DAPACHE1"
     CFLAGS="$CFLAGS $DB2_CFLAGS"
   ConfigEnd
   MODULE-DEFINITION-END
*/

#define MODULE_RELEASE "mod_auth_ibmdb2/0.8.2"

#ifdef APACHE2
#define PCALLOC apr_pcalloc
#define SNPRINTF apr_snprintf
#define PSTRDUP apr_pstrdup
#else
#define PCALLOC ap_pcalloc
#define SNPRINTF ap_snprintf
#define PSTRDUP ap_pstrdup
#endif

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "sqlcli1.h"
#ifdef APACHE2
#include "http_request.h"   				/* for ap_hook_(check_user_id | auth_checker) */
#include "apr_env.h"
#endif
#include "md5_crypt.h"						/* routines for validate_pw function */

#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <gdbm.h>

#define MAX_IBMDB2_UID_LENGTH   18
#define MAX_IBMDB2_PWD_LENGTH   30
#define MAX_UID_LENGTH          32
#define MAX_PWD_LENGTH          64
#define MAX_GRP_LENGTH         128


typedef struct {
        char   password[MAX_PWD_LENGTH];
        time_t timestamp;
} cached_password_timestamp;


typedef struct {
        int    numgrps;
        time_t timestamp;
} cached_group_timestamp;


#ifndef FALSE								/* FALSE */
#define FALSE 0
#endif
#ifndef TRUE								/* TRUE */
#define TRUE (!FALSE)
#endif


/*
 * Error Logging (LOG_ERROR, LOG_DBG)
 */

#ifdef APACHE2
#define LOG_DBG( msg ) ap_log_rerror( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, r, "%s", msg )
#define LOG_DBGS( msg ) ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, s, "%s", msg )
#define LOG_ERROR( msg ) ap_log_rerror( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "%s", msg )
#else
#define LOG_DBG( msg ) ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, r->server, "%s", msg )
#define LOG_ERROR( msg ) ap_log_error( APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r->server, "%s", msg )
#endif

#define MAXERRLEN 1024

/*
 * structure to hold the configuration details for the request
 */
typedef struct  {
  char *ibmdb2user;							/* user ID to connect to db server */
  char *ibmdb2passwd;						/* password to connect to db server */
  char *ibmdb2DB;							/* Database name */
  char *ibmdb2pwtable;						/* user password table */
  char *ibmdb2grptable;						/* user group table */
  char *ibmdb2NameField;					/* field in password/grp table with username */
  char *ibmdb2PasswordField;				/* field in password table with password */
  char *ibmdb2GroupField;					/* field in group table with group name */
  int  ibmdb2Crypted;						/* are passwords encrypted? */
  int  ibmdb2KeepAlive;						/* keep connection persistent? */
  int  ibmdb2Authoritative;					/* are we authoritative? */
  int  ibmdb2NoPasswd;						/* do we ignore password? */
  char *ibmdb2UserCondition; 				/* Condition to add to the user where-clause in select query */
  char *ibmdb2GroupCondition; 				/* Condition to add to the group where-clause in select query */
  int  ibmdb2caching;						/* are user credentials cached? */
  int  ibmdb2grpcaching;					/* is group information cached? */
  char *ibmdb2cachefile;					/* path to cache file */
  char *ibmdb2cachelifetime;				/* cache lifetime in seconds */
} ibmdb2_auth_config_rec;

/*
 * Global environment and connection handles to db. If AuthIBMDB2KeepAlive
 * is 'On', the connection is persisted across requests.
 * Need some other handwaving to validate connection still good...
 *
 */

static SQLHANDLE   henv;    				/* environment handle   */
static SQLHANDLE   hdbc;    				/* db connection handle */

static int write_group_cache( request_rec *r, const char *user, const char **grplist, ibmdb2_auth_config_rec *m );
static char **read_group_cache( request_rec *r, const char *user, ibmdb2_auth_config_rec *m );

/*
 * Callback to close ibmdb2 handle when necessary.  Also called when a
 * child httpd process is terminated.
 */
#ifdef APACHE2
static apr_status_t
#else
static void
#endif
mod_auth_ibmdb2_cleanup (void *notused)
{
    SQLDisconnect( hdbc );                 	/* disconnect the database connection */
    SQLFreeHandle( SQL_HANDLE_DBC, hdbc ); 	/* free the connection handle         */
    SQLFreeHandle( SQL_HANDLE_ENV, henv );  /* free the environment handle        */
#ifdef APACHE2
    return 0;
#endif
}

/*
 * empty function necessary because register_cleanup requires it as one
 * of its parameters
 */
#ifdef APACHE2
static apr_status_t
#else
static void
#endif
mod_auth_ibmdb2_cleanup_child (void *notused)
{
	/* nothing */
#ifdef APACHE2
    return 0;
#endif
}


#ifdef APACHE1
/*
 * handler to do cleanup on child exit
 */
static void child_exit( server_rec *s, pool *p )
{
	mod_auth_ibmdb2_cleanup(NULL);
}
#endif

/* int validate_pw( const char *sent, const char *real ); */

/* function to validate the password */

int validate_pw( const char *sent, const char *real )
{
	unsigned int i = 0;
	char *result;

	char ident[80];

	if( real[0] == '$' && strlen(real) > 31)
	{
		ident[0] = '$';
		while( real[++i] != '$' && i < strlen(real) )
		   ident[i] = real[i];
		ident[i] = '$'; i++; ident[i] = '\0';

        result = encode_md5( sent, real, ident );

	}
	else if( strlen( real ) == 32 )
	{
		result = md5( (char*)sent );
	}
	else
	{
		result = crypt( sent, real );
    }

	if( strcmp( real, result ) == 0 )
	   return TRUE;
	else
	   return FALSE;

}

/*
 * structure to hold the sqlca variables
 */
typedef struct
{
	char msg[SQL_MAX_MESSAGE_LENGTH + 1];
	char state[SQL_SQLSTATE_SIZE + 1];
	int code;
} sqlerr_t;

//	function to check the environment/connection handle and to return the sqlca structure

sqlerr_t get_handle_err( SQLSMALLINT htype, SQLHANDLE handle, SQLRETURN rc )
{
	SQLCHAR message[SQL_MAX_MESSAGE_LENGTH + 1];
	SQLCHAR SQLSTATE[SQL_SQLSTATE_SIZE + 1];
	SQLINTEGER sqlcode;
	SQLSMALLINT length;

	sqlerr_t sqlerr;

	if (rc != SQL_SUCCESS)
	{
		switch( rc )
		{
			case SQL_INVALID_HANDLE:
				strcpy( sqlerr.msg, "SQL_INVALID_HANDLE" );
				break;
			case SQL_SUCCESS_WITH_INFO:
				strcpy( sqlerr.msg, "SQL_SUCCESS_WITH_INFO" );
				break;
			case SQL_ERROR:
				SQLGetDiagRec(htype, handle, 1, SQLSTATE, &sqlcode, message, SQL_MAX_MESSAGE_LENGTH + 1, &length);
				strcpy( sqlerr.msg, message );
				strcpy( sqlerr.state, SQLSTATE );
				sqlerr.code = sqlcode;
				break;
			default:
				break;
		}
		return sqlerr;
	}
}

/* function to check the statement handle and to return the sqlca structure */

sqlerr_t get_stmt_err( SQLHANDLE stmt, SQLRETURN rc )
{
	SQLCHAR message[SQL_MAX_MESSAGE_LENGTH + 1];
	SQLCHAR SQLSTATE[SQL_SQLSTATE_SIZE + 1];
	SQLINTEGER sqlcode;
    SQLSMALLINT length;

    sqlerr_t sqlerr;

    if (rc != SQL_SUCCESS)
    {
		SQLGetDiagRec(SQL_HANDLE_STMT, stmt, 1, SQLSTATE, &sqlcode, message, SQL_MAX_MESSAGE_LENGTH + 1, &length);

		strcpy( sqlerr.msg, message );
		strcpy( sqlerr.state, SQLSTATE );
		sqlerr.code = sqlcode;

		return sqlerr;
	}
}

/*
 * open connection to DB server if necessary.  Return TRUE if connection
 * is good, FALSE if not able to connect.  If false returned, reason
 * for failure has been logged to error_log file already.
 */

/* ibmdb2_connect - connect to db */

SQLRETURN ibmdb2_connect( request_rec *r, ibmdb2_auth_config_rec *m )
{
    char errmsg[MAXERRLEN];
    char *db  = NULL;
    char *uid = NULL;
    char *pwd = NULL;
    sqlerr_t sqlerr;
    SQLRETURN   sqlrc;
    SQLINTEGER  dead_conn = SQL_CD_TRUE; 	/* initialize to 'conn is dead' */

    /* test the database connection */
    sqlrc = SQLGetConnectAttr( hdbc, SQL_ATTR_CONNECTION_DEAD, &dead_conn, 0, NULL ) ;

    if( dead_conn == SQL_CD_FALSE )			/* then the connection is alive */
    {
       LOG_DBG( "  DB connection is alive; re-using" );
       return SQL_SUCCESS;
    }
    else 									/* connection is dead or not yet existent */
    {
       LOG_DBG( "  DB connection is dead or nonexistent; create connection" );
    }

	LOG_DBG( "  allocate an environment handle" );

    /* allocate an environment handle */

	sqlrc = SQLAllocHandle( SQL_HANDLE_ENV, SQL_NULL_HANDLE, &henv );
	
	if( sqlrc != SQL_SUCCESS )
	{
		sqlerr = get_handle_err( SQL_HANDLE_ENV, henv, sqlrc );
		LOG_ERROR( "IBMDB2 error: cannot allocate an environment handle" );
		LOG_DBG( sqlerr.msg );
		return( SQL_ERROR );
	}

    /* allocate a connection handle     */

	sqlrc = SQLAllocHandle( SQL_HANDLE_DBC, henv, &hdbc );
	
	if( sqlrc != SQL_SUCCESS )
	{
		sqlerr = get_handle_err( SQL_HANDLE_ENV, henv, sqlrc );
		LOG_ERROR( "IBMDB2 error: cannot allocate a connection handle" );
		LOG_DBG( sqlerr.msg );
		return( SQL_ERROR );
	}

    /* Set AUTOCOMMIT ON (all we are doing are SELECTs) */

    if( SQLSetConnectAttr( hdbc, SQL_ATTR_AUTOCOMMIT, ( void * ) SQL_AUTOCOMMIT_ON, SQL_NTS ) != SQL_SUCCESS )
    {
	   LOG_ERROR( "IBMDB2 error: cannot set autocommit on" );
       return( SQL_ERROR ) ;
    }

    /* make the database connection */

    uid = m->ibmdb2user;
    pwd = m->ibmdb2passwd;
    db  = m->ibmdb2DB;

    if( SQLConnect( hdbc, db, SQL_NTS, uid, SQL_NTS, pwd, SQL_NTS ) != SQL_SUCCESS )
    {
	   sprintf( errmsg, "IBMDB2 error: cannot connect to %s", db );
	   LOG_ERROR( errmsg );
       SQLDisconnect( hdbc ) ;
       SQLFreeHandle( SQL_HANDLE_DBC, hdbc ) ;
       return( SQL_ERROR ) ;
    }

    /* ELSE: connection was successful */

    /* make sure dbconn is closed at end of request if specified */

    if( !m->ibmdb2KeepAlive )				/* close db connection when request done */
    {
#ifdef APACHE2
       apr_pool_cleanup_register
#else
       ap_register_cleanup
#endif
       (r->pool, (void *)NULL,
 			  mod_auth_ibmdb2_cleanup,
 			  mod_auth_ibmdb2_cleanup_child);
    }

    return SQL_SUCCESS;
}

/* ibmdb2_disconnect - disconnect from db */

SQLRETURN ibmdb2_disconnect( request_rec *r, ibmdb2_auth_config_rec *m )
{

    if( m->ibmdb2KeepAlive )				/* if persisting dbconn, return without disconnecting */
    {
       LOG_DBG( "  keepalive on; do not disconnect from database" );
       return( SQL_SUCCESS );
    }

    LOG_DBG( "  keepalive off; disconnect from database" );

    SQLDisconnect( hdbc ) ;

	LOG_DBG( "  free connection handle" );

    /* free the connection handle */

    SQLFreeHandle( SQL_HANDLE_DBC, hdbc ) ;

    LOG_DBG( "  free environment handle" );

    /* free the environment handle */

    SQLFreeHandle( SQL_HANDLE_ENV, henv ) ;

    return( SQL_SUCCESS );
}


#ifdef APACHE2
static void *
create_ibmdb2_auth_dir_config( apr_pool_t *p, char *d )
#else
static void *
create_ibmdb2_auth_dir_config( pool *p, char *d )
#endif
{
  ibmdb2_auth_config_rec *m = PCALLOC(p, sizeof(ibmdb2_auth_config_rec));
  if( !m ) return NULL;						/* failure to get memory is a bad thing */

  /* DEFAULT values */

  m->ibmdb2NameField     = "username";
  m->ibmdb2PasswordField = "password";
  m->ibmdb2GroupField    = "groupname";
  m->ibmdb2Crypted       = 1;              			/* passwords are encrypted */
  m->ibmdb2KeepAlive     = 1;             			/* keep persistent connection */
  m->ibmdb2Authoritative = 1;              			/* we are authoritative source for users */
  m->ibmdb2NoPasswd      = 0;              			/* we require password */
  m->ibmdb2caching       = 0;						/* user caching is turned off */
  m->ibmdb2grpcaching    = 0;						/* group caching is turned off */
  m->ibmdb2cachefile     = "/tmp/auth_cred_cache";	/* default cachefile */
  m->ibmdb2cachelifetime = "300";					/* cache expires in 300 seconds (5 minutes) */

  return (void *)m;
}

#ifdef APACHE2
static
command_rec ibmdb2_auth_cmds[] = {
	AP_INIT_TAKE1("AuthIBMDB2User", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2user),
	OR_AUTHCFG, "ibmdb2 server user name"),

	AP_INIT_TAKE1("AuthIBMDB2Password", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2passwd),
	OR_AUTHCFG, "ibmdb2 server user password"),

	AP_INIT_TAKE1("AuthIBMDB2Database", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2DB),
	OR_AUTHCFG, "ibmdb2 database name"),

	AP_INIT_TAKE1("AuthIBMDB2UserTable", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2pwtable),
	OR_AUTHCFG, "ibmdb2 user table name"),

	AP_INIT_TAKE1("AuthIBMDB2GroupTable", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2grptable),
	OR_AUTHCFG, "ibmdb2 group table name"),

	AP_INIT_TAKE1("AuthIBMDB2NameField", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2NameField),
	OR_AUTHCFG, "ibmdb2 User ID field name within table"),

	AP_INIT_TAKE1("AuthIBMDB2GroupField", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2GroupField),
	OR_AUTHCFG, "ibmdb2 Group field name within table"),

	AP_INIT_TAKE1("AuthIBMDB2PasswordField", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2PasswordField),
	OR_AUTHCFG, "ibmdb2 Password field name within table"),

	AP_INIT_FLAG("AuthIBMDB2CryptedPasswords", ap_set_flag_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2Crypted),
	OR_AUTHCFG, "ibmdb2 passwords are stored encrypted if On"),

	AP_INIT_FLAG("AuthIBMDB2KeepAlive", ap_set_flag_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2KeepAlive),
	OR_AUTHCFG, "ibmdb2 connection kept open across requests if On"),

	AP_INIT_FLAG("AuthIBMDB2Authoritative", ap_set_flag_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2Authoritative),
	OR_AUTHCFG, "ibmdb2 lookup is authoritative if On"),

	AP_INIT_FLAG("AuthIBMDB2NoPasswd", ap_set_flag_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2NoPasswd),
	OR_AUTHCFG, "If On, only check if user exists; ignore password"),

	AP_INIT_TAKE1("AuthIBMDB2UserCondition", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2UserCondition),
	OR_AUTHCFG, "condition to add to user where-clause"),

	AP_INIT_TAKE1("AuthIBMDB2GroupCondition", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2GroupCondition),
	OR_AUTHCFG, "condition to add to group where-clause"),

	AP_INIT_FLAG("AuthIBMDB2Caching", ap_set_flag_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2caching),
	OR_AUTHCFG, "If On, user credentials are cached"),

	AP_INIT_FLAG("AuthIBMDB2GroupCaching", ap_set_flag_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2grpcaching),
	OR_AUTHCFG, "If On, group information is cached"),

	AP_INIT_TAKE1("AuthIBMDB2CacheFile", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2cachefile),
	OR_AUTHCFG, "cachefile where user credentials are stored"),

	AP_INIT_TAKE1("AuthIBMDB2CacheLifetime", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2cachelifetime),
	OR_AUTHCFG, "cache lifetime in seconds"),

  { NULL }
};
#else
static
command_rec ibmdb2_auth_cmds[] = {
  { "AuthIBMDB2User", ap_set_string_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2user),
    OR_AUTHCFG, TAKE1, "ibmdb2 server user name" },

  { "AuthIBMDB2Password", ap_set_string_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2passwd),
    OR_AUTHCFG, TAKE1, "ibmdb2 server user password" },

  { "AuthIBMDB2Database", ap_set_string_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2DB),
    OR_AUTHCFG, TAKE1, "ibmdb2 database name" },

  { "AuthIBMDB2UserTable", ap_set_string_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2pwtable),
    OR_AUTHCFG, TAKE1, "ibmdb2 user table name" },

  { "AuthIBMDB2GroupTable", ap_set_string_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2grptable),
    OR_AUTHCFG, TAKE1, "ibmdb2 group table name" },

  { "AuthIBMDB2NameField", ap_set_string_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2NameField),
    OR_AUTHCFG, TAKE1, "ibmdb2 User ID field name within table" },

  { "AuthIBMDB2GroupField", ap_set_string_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2GroupField),
    OR_AUTHCFG, TAKE1, "ibmdb2 Group field name within table" },

  { "AuthIBMDB2PasswordField", ap_set_string_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2PasswordField),
    OR_AUTHCFG, TAKE1, "ibmdb2 Password field name within table" },

  { "AuthIBMDB2CryptedPasswords", ap_set_flag_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2Crypted),
    OR_AUTHCFG, FLAG, "ibmdb2 passwords are stored encrypted if On" },

  { "AuthIBMDB2KeepAlive", ap_set_flag_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2KeepAlive),
    OR_AUTHCFG, FLAG, "ibmdb2 connection kept open across requests if On" },

  { "AuthIBMDB2Authoritative", ap_set_flag_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2Authoritative),
    OR_AUTHCFG, FLAG, "ibmdb2 lookup is authoritative if On" },

  { "AuthIBMDB2NoPasswd", ap_set_flag_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2NoPasswd),
    OR_AUTHCFG, FLAG, "If On, only check if user exists; ignore password" },

  { "AuthIBMDB2UserCondition", ap_set_string_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2UserCondition),
    OR_AUTHCFG, TAKE1, "condition to add to user where-clause" },

  { "AuthIBMDB2GroupCondition", ap_set_string_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2GroupCondition),
    OR_AUTHCFG, TAKE1, "condition to add to group where-clause" },

  { "AuthIBMDB2Caching", ap_set_flag_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2caching),
    OR_AUTHCFG, FLAG, "If On, user credentials are cached" },

  { "AuthIBMDB2GroupCaching", ap_set_flag_slot,
      (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2grpcaching),
    OR_AUTHCFG, FLAG, "If On, group information is cached" },

  { "AuthIBMDB2CacheFile", ap_set_string_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2cachefile),
    OR_AUTHCFG, TAKE1, "cachefile where user credentials are stored" },

  { "AuthIBMDB2CacheLifetime", ap_set_string_slot,
    (void*)XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2cachelifetime),
    OR_AUTHCFG, TAKE1, "cache lifetime in seconds" },

  { NULL }
};
#endif


#ifdef APACHE2
module AP_MODULE_DECLARE_DATA ibmdb2_auth_module;
#else
module ibmdb2_auth_module;
#endif

#ifdef APACHE2
static int mod_auth_ibmdb2_init_handler( apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s )
{
	char errmsg[MAXERRLEN];
	char *env;

	ap_add_version_component( p, MODULE_RELEASE );

	errmsg[0] = '\0';
	if( apr_env_get( &env, "DB2INSTANCE", p ) != APR_SUCCESS )
		sprintf( errmsg, "DB2INSTANCE=[%s]", "not set" );
	else
		sprintf( errmsg, "DB2INSTANCE=[%s]", env );
	LOG_DBGS( errmsg );
	
	errmsg[0] = '\0';
	if( apr_env_get( &env, "LD_LIBRARY_PATH", p ) != APR_SUCCESS )
		sprintf( errmsg, "LD_LIBRARY_PATH=[%s]", "not set" );
	else
		sprintf( errmsg, "LD_LIBRARY_PATH=[%s]", env );
	LOG_DBGS( errmsg );

    return OK;
}
#else
static void mod_auth_ibmdb2_init_handler(server_rec *s, pool *p)
{
	ap_add_version_component( MODULE_RELEASE );
}
#endif

/*
 * Fetch and return password string from database for named user.
 * If we are in NoPasswd mode, returns user name instead.
 * If user or password not found, returns NULL
 */

static char *get_ibmdb2_pw( request_rec *r, char *user, ibmdb2_auth_config_rec *m )
{
	int         rowcount = 0;

	char        errmsg[MAXERRLEN];
    int         rc = 0;
    char        query[MAX_STRING_LEN];
    char        *pw = NULL;
    sqlerr_t	sqlerr;
    SQLHANDLE   hstmt;   					/* statement handle     */
    SQLRETURN   sqlrc = SQL_SUCCESS;

    struct
    {
       SQLINTEGER ind ;
       SQLCHAR    val[MAX_PWD_LENGTH] ;
    } passwd ;         						/* variable to get data from the PASSWD column */

    LOG_DBG( "begin get_ibmdb2_pw()" );

    /* Connect to the data source */
    if( ibmdb2_connect( r, m ) != SQL_SUCCESS )
    {
		LOG_DBG( "    ibmdb2_connect() cannot connect!" );

        return NULL;
    }


   /*
    * If we are not checking for passwords, there may not be a password field
    * in the database.  We just look up the name field value in this case
    * since it is guaranteed to exist.
    */
    if( m->ibmdb2NoPasswd )
    {
        m->ibmdb2PasswordField = m->ibmdb2NameField;
    }

    /* construct SQL query */

    if( m->ibmdb2UserCondition )
    {
		SNPRINTF( query, sizeof(query)-1, "SELECT rtrim(%s) FROM %s WHERE %s='%s' AND %s",
	       m->ibmdb2PasswordField, m->ibmdb2pwtable, m->ibmdb2NameField,
	       user, m->ibmdb2UserCondition);
    }
    else
    {
		SNPRINTF( query, sizeof(query)-1, "SELECT rtrim(%s) FROM %s WHERE %s='%s'",
	       m->ibmdb2PasswordField, m->ibmdb2pwtable, m->ibmdb2NameField,
           user);
    }

    sprintf( errmsg, "    query=[%s]", query );
    LOG_DBG( errmsg );

    LOG_DBG( "    allocate a statement handle" );

    /* allocate a statement handle */

    sqlrc = SQLAllocHandle( SQL_HANDLE_STMT, hdbc, &hstmt ) ;

    LOG_DBG( "    prepare the statement" );

    /* prepare the statement */

    sqlrc = SQLPrepare( hstmt, query, SQL_NTS ) ;

    /* Maybe implemented later - later binding of username

    errmsg[0] = '\0';
    sprintf( errmsg, "bind username '%s' to the statement", user );
    LOG_DBG( errmsg );

    sqlrc = SQLBindParameter(hstmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR,
                              SQL_VARCHAR, MAX_UID_LENGTH, 0, user, MAX_UID_LENGTH, NULL);

    */

    LOG_DBG( "    execute the statement" );

    /* execute the statement for username */

    sqlrc = SQLExecute( hstmt ) ;

    if( sqlrc != SQL_SUCCESS )				/* check statement */
	{
		sqlerr = get_stmt_err( hstmt, sqlrc );

		errmsg[0] = '\0';

		switch( sqlerr.code )
		{
			case -204:						/* the table does not exist */
			   sprintf( errmsg, "table [%s] does not exist", m->ibmdb2pwtable );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -206:						/* the column does not exist */
			   sprintf( errmsg, "column [%s] or [%s] does not exist (or both)", m->ibmdb2PasswordField, m->ibmdb2NameField );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -551:						/* no privilege to access table */
			   sprintf( errmsg, "user [%s] does not have the privilege to access table [%s]", m->ibmdb2user, m->ibmdb2pwtable );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -10:						/* syntax error in user condition [string delimiter] */
			case -104:						/* syntax error in user condition [unexpected token] */
			   sprintf( errmsg, "syntax error in user condition [%s]", m->ibmdb2UserCondition );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
		    default:
			   LOG_ERROR( "IBMDB2 error: statement cannot be processed" );
			   LOG_DBG( sqlerr.msg );
			   return NULL;
		       break;
		}
	}

    LOG_DBG( "    fetch each row, and display" );

    /* fetch each row, and display */

    sqlrc = SQLFetch( hstmt );

    if( sqlrc == SQL_NO_DATA_FOUND )
    {
		LOG_DBG( "    query returned no data!" );
    }
    else
    {
		while( sqlrc != SQL_NO_DATA_FOUND )
	    {
		    rowcount++;

		    LOG_DBG( "    get data from query resultset" );

		    sqlrc = SQLGetData( hstmt, 1, SQL_C_CHAR, passwd.val, MAX_PWD_LENGTH,
                                &passwd.ind ) ;

            errmsg[0] = '\0';
            sprintf( errmsg, "    password from database=[%s]", passwd.val );
            LOG_DBG( errmsg );

            LOG_DBG( "    call SQLFetch() (point to next row)" );

            sqlrc = SQLFetch( hstmt );
		}
	}

    LOG_DBG( "    free statement handle" );

    /* free the statement handle */

    sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;

    /* disconnect from the data source */

    ibmdb2_disconnect( r, m ) ;

    LOG_DBG( "end get_ibmdb2_pw()" );

    if( rowcount > 1 )
    {
		LOG_ERROR( "query returns more than 1 row -> ooops (forgot pk on username?)" );
        return NULL;
    }

    pw = (char *)PSTRDUP(r->pool, passwd.val);
    return pw;

}

/*
 * get list of groups from database.  Returns array of pointers to strings
 * the last of which is NULL.  returns NULL pointer if user is not member
 * of any groups.
 */

static char **get_ibmdb2_groups( request_rec *r, char *user, ibmdb2_auth_config_rec *m )
{
	char        *gname = NULL;
    char        **list = NULL;
    char        **cachelist = NULL;
    char        query[MAX_STRING_LEN];
    char 		errmsg[MAXERRLEN];
    int         rowcount = 0;
    int         rc      = 0;
    int         numgrps = 0;
    sqlerr_t	sqlerr;
    SQLHANDLE   hstmt;   					/* statement handle     */
    SQLRETURN   sqlrc = SQL_SUCCESS;

    struct {
       SQLINTEGER ind ;
       SQLCHAR    val[MAX_PWD_LENGTH] ;
    } group ;         						/* variable to get data from the GROUPNAME column */

    typedef struct element
	{
	   char data[MAX_GRP_LENGTH];
	   struct element *next;
	} linkedlist_t;

	linkedlist_t *element, *first;

	/* read group cache */

	if( m->ibmdb2grpcaching )
	{
		cachelist = read_group_cache( r, user, m );

		if( cachelist != NULL )
		{
			return cachelist;
		}
	}

    LOG_DBG( "begin get_ibmdb2_groups()" );

    /* Connect to the data source */
    if( ibmdb2_connect( r, m ) != SQL_SUCCESS )
    {
		LOG_DBG( "   ibmdb2_connect() cannot connect!" );

        return NULL;
    }

    /* construct SQL query */

	if( m->ibmdb2GroupCondition )
	{
		SNPRINTF( query, sizeof(query)-1, "SELECT rtrim(%s) FROM %s WHERE %s='%s' AND %s",
	       m->ibmdb2GroupField, m->ibmdb2grptable, m->ibmdb2NameField,
	       user, m->ibmdb2GroupCondition);
	}
	else
	{
		SNPRINTF( query, sizeof(query)-1, "SELECT rtrim(%s) FROM %s WHERE %s='%s'",
	       m->ibmdb2GroupField, m->ibmdb2grptable, m->ibmdb2NameField,
	       user);
	}

	errmsg[0] = '\0';
	sprintf( errmsg, "    query=[%s]", query );
	LOG_DBG( errmsg );

	LOG_DBG( "    allocate a statement handle" );

	/* allocate a statement handle */

	sqlrc = SQLAllocHandle( SQL_HANDLE_STMT, hdbc, &hstmt ) ;

	LOG_DBG( "    prepare the statement" );

	/* prepare the statement */

	sqlrc = SQLPrepare( hstmt, query, SQL_NTS ) ;

	/* Maybe implemented later - later binding of username

	errmsg[0] = '\0';
	sprintf( errmsg, "bind username '%s' to the statement", user );
	LOG_DBG( errmsg );

	sqlrc = SQLBindParameter(hstmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR,
	                          SQL_VARCHAR, MAX_UID_LENGTH, 0, user, MAX_UID_LENGTH, NULL);

	*/

	LOG_DBG( "    execute the statement" );

	/* execute the statement for username */

	sqlrc = SQLExecute( hstmt ) ;

    if( sqlrc != SQL_SUCCESS )				/* check statement */
	{
		sqlerr = get_stmt_err( hstmt, sqlrc );

		errmsg[0] = '\0';

		switch( sqlerr.code )
		{
			case -204:						/* the table does not exist */
			   sprintf( errmsg, "table [%s] does not exist", m->ibmdb2grptable );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -206:						/* the column does not exist */
			   sprintf( errmsg, "column [%s] or [%s] does not exist (or both)", m->ibmdb2GroupField, m->ibmdb2NameField );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -551:						/* no privilege to access table */
			   sprintf( errmsg, "user [%s] does not have the privilege to access table [%s]", m->ibmdb2user, m->ibmdb2grptable );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -10:						/* syntax error in group condition [string delimiter] */
			case -104:						/* syntax error in group condition [unexpected token] */
			   sprintf( errmsg, "syntax error in group condition [%s]", m->ibmdb2GroupCondition );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
		    default:
			   LOG_ERROR( "IBMDB2 error: statement cannot be processed" );
			   LOG_DBG( sqlerr.msg );
			   return NULL;
		       break;
		}
	}

	LOG_DBG( "    fetch each row, and display" );

	/* fetch each row, and display */

	sqlrc = SQLFetch( hstmt );

	element = (linkedlist_t *)malloc(sizeof(linkedlist_t));
	first = element;


	if( sqlrc == SQL_NO_DATA_FOUND )
	{
		LOG_DBG( "    query returned no data!" );
		return NULL;
	}
	else
	{
		/* Building linked list */

		element->next = NULL;

		while( sqlrc != SQL_NO_DATA_FOUND )
	    {
		    rowcount++;						/* record counter */

		    LOG_DBG( "    get data from query resultset" );

		    sqlrc = SQLGetData( hstmt, 1, SQL_C_CHAR, group.val, MAX_GRP_LENGTH,
	                            &group.ind ) ;

	        if( element->next == NULL )
			{
				strcpy( element->data, group.val );
				element->next = malloc(sizeof(linkedlist_t));
				element = element->next;
				element->next = NULL;
            }

	        errmsg[0] = '\0';
	        sprintf( errmsg, "    group #%i from database=[%s]", rowcount, group.val );
	        LOG_DBG( errmsg );

	        LOG_DBG( "    call SQLFetch() (point to next row)" );

	        sqlrc = SQLFetch( hstmt );
		}
	}

	LOG_DBG( "    free statement handle" );

	/* free the statement handle */

	sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;

	/* disconnect from the data source */

	ibmdb2_disconnect( r, m ) ;

	LOG_DBG( "end get_ibmdb2_groups()" );

	/* Building list to be returned */

	numgrps = 0;

	list = (char **) PCALLOC(r->pool, sizeof(char *) * (rowcount+1));

	element = first;

	while( element->next != NULL )
	{
		if( element->data )
		   list[numgrps] = (char *) PSTRDUP(r->pool, element->data);
		else
		   list[numgrps] = "";				/* if no data, make it empty, not NULL */

		numgrps++;
	    element=element->next;
    }

    list[numgrps] = NULL;           		/* last element in array is NULL */

    /* Free memory of linked list */

    element = first;

	while( first->next != NULL )
	{
		first = element->next;
	    free(element);
	    element=first;
	}

    free(first);

    /* End of freeing memory of linked list */

    /* write group cache */

    if( m->ibmdb2grpcaching )
    {
		write_group_cache( r, user, (const char**)list, m );
	}

    /* Returning list */

    return list;

}

/*
 * function to store the user credentials in the local cache, so that subsequent
 * http requests can validate the user directly from local cache without the need
 * to query the backend db2 database.
 */

static int write_cache( request_rec *r, const char *user, const char *password, ibmdb2_auth_config_rec *m )
{
	char errmsg[MAXERRLEN];

	char *my_user = (char *)user;
	datum datum_user = { my_user, (strlen( my_user )+1) };

	cached_password_timestamp cpt;

	datum datum_value;
	GDBM_FILE gdbm;

	char *my_password = (char *)password;
	strcpy(cpt.password, my_password);

	if ( !(time(&(cpt.timestamp))) )
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "unable to determine current time (write cache)");
		LOG_ERROR( errmsg );
		return( 1 );
	}

	datum_value.dptr = (void *)&cpt;
	datum_value.dsize = sizeof(cpt);

	gdbm = gdbm_open( m->ibmdb2cachefile, 0, GDBM_WRCREAT, 00664, NULL );

	if ( gdbm != NULL )
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "storing user [%s] and pass [%s] in cache", my_user, my_password);
		LOG_DBG( errmsg );

		if( gdbm_store( gdbm, datum_user, datum_value, GDBM_REPLACE ) != 0 )
		{
			errmsg[0] = '\0';
			sprintf( errmsg, "unable to store user [%s] in cache", my_user);
			LOG_DBG( errmsg );
		}

		gdbm_close( gdbm );
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "could not open cachefile [%s] for writing", m->ibmdb2cachefile );
		LOG_ERROR( errmsg );
	}

	return( 0 );
}

/*
 * function to check in the local cache to validate user, otherwise
 * we need to query the backend db2 database.
 */

static char *read_cache( request_rec *r, const char *user, ibmdb2_auth_config_rec *m )
{
	char errmsg[MAXERRLEN];

	char *my_user = (char *)user;
	datum datum_user = { my_user, (strlen( my_user )+1) };

	cached_password_timestamp cpt;
	time_t current_time;

	datum datum_value;

	char *pw = NULL;

	int MAXAGE = atoi( m->ibmdb2cachelifetime );

	GDBM_FILE gdbm;

	double time_diff;

	gdbm = gdbm_open( m->ibmdb2cachefile, 0, GDBM_WRCREAT, 00664, NULL );

	if( gdbm != NULL )
	{
		datum_value = gdbm_fetch( gdbm, datum_user );

		if( datum_value.dptr != NULL )
		{
			if( datum_value.dsize != sizeof(cpt) )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "we found our user in the cache but with corrupted record: %s \n", my_user);
				LOG_ERROR( errmsg );
				gdbm_close( gdbm );

				return NULL;
			}
			else
			{
				memcpy((void *)&cpt, datum_value.dptr, datum_value.dsize);

				if( !(time(&(current_time))) )
				{
					errmsg[0] = '\0';
					sprintf( errmsg, "unable to determine current time (read cache)");
					LOG_ERROR( errmsg );
					gdbm_close( gdbm );

					return NULL;
				}

				time_diff = difftime( current_time, cpt.timestamp );

				if( MAXAGE < time_diff )
				{
					errmsg[0] = '\0';
					sprintf( errmsg, "cached password for user [%s] is toooo old", my_user);
					LOG_DBG( errmsg );
					gdbm_close( gdbm );

					return NULL;
				}

				pw = cpt.password;

				/* Congratulations, we have a fresh cached entry */
				errmsg[0] = '\0';
				sprintf( errmsg, "user [%s] - [%s] found in cache", my_user, pw);
				LOG_DBG( errmsg );
				gdbm_close(gdbm);

				return pw;
			}
		}
		else
		{
			/* Did not find user in the cache */
			errmsg[0] = '\0';
			sprintf( errmsg, "user [%s] not found in cache", my_user);
			LOG_DBG( errmsg );
			gdbm_close( gdbm );

			return NULL;
		}
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "could not open cachefile [%s] for reading", m->ibmdb2cachefile );
		LOG_ERROR( errmsg );

		return NULL;
	}
}

/*
 * function to store the group information in the local cache, so that subsequent
 * http requests can validate the groups directly from local cache without the need
 * to query the backend db2 database.
 */

static int write_group_cache( request_rec *r, const char *user, const char **grplist, ibmdb2_auth_config_rec *m )
{
	char errmsg[MAXERRLEN];

	char ibmdb2grpcachefile[512];
	char username[MAX_UID_LENGTH+4];
	char groupname[MAX_GRP_LENGTH];

	int i = 0;

	char *my_user = (char *)user;
	datum datum_user = { my_user, (strlen( my_user )+1) };

	cached_group_timestamp cgt;

	datum datum_value;
	datum key_data;
	datum data_data;

	GDBM_FILE gdbm;

	sprintf( ibmdb2grpcachefile, "%s.grp", m->ibmdb2cachefile );

	if ( !(time(&(cgt.timestamp))) )
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "unable to determine current time (write group cache)");
		LOG_ERROR( errmsg );
		return( 1 );
	}

	while( grplist[i] )
	{
		++i;
	}

	cgt.numgrps = i;

	datum_value.dptr = (void *)&cgt;
	datum_value.dsize = sizeof(cgt);

	gdbm = gdbm_open( ibmdb2grpcachefile, 0, GDBM_WRCREAT, 00664, NULL );

	if ( gdbm != NULL )
	{
		if( gdbm_store( gdbm, datum_user, datum_value, GDBM_REPLACE ) != 0 )
		{
			errmsg[0] = '\0';
			sprintf( errmsg, "unable to store group info for user [%s] in cache", my_user);
			LOG_DBG( errmsg );

			gdbm_close( gdbm );

	        return( 1 );
		}

		i = 0;

		while( grplist[i] )
		{
			key_data.dptr = NULL;
            data_data.dptr = NULL;

			username[0] = '\0';
			sprintf( username, "%s_%d", my_user, i );

			groupname[0] = '\0';
			strcpy( groupname, grplist[i] );

			key_data.dptr = username;
			key_data.dsize = strlen(username) + 1;

			data_data.dptr = groupname;
			data_data.dsize = strlen(groupname) + 1;

			if( gdbm_store( gdbm, key_data, data_data, GDBM_REPLACE ) != 0 )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "unable to store group [%s] for user [%s] in cache", grplist[i], my_user );
			    LOG_DBG( errmsg );

			    gdbm_close( gdbm );

			    return( 1 );
			}
			else
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "storing user [%s] and group [%s] in cache", my_user, grplist[i] );
				LOG_DBG( errmsg );
			}

			++i;
		}

		gdbm_close( gdbm );
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "could not open group cachefile [%s] for writing", ibmdb2grpcachefile );
		LOG_ERROR( errmsg );
	}

	return( 0 );
}

/*
 * function to check in the local cache to check if user is in a group, otherwise
 * we need to query the backend db2 database.
 */

static char **read_group_cache( request_rec *r, const char *user, ibmdb2_auth_config_rec *m )
{
	char errmsg[MAXERRLEN];

	char ibmdb2grpcachefile[512];
	char username[MAX_UID_LENGTH+4];

	int i = 0;

	int numgrps;

	char *my_user = (char *)user;
	datum datum_user = { my_user, (strlen( my_user )+1) };

	cached_group_timestamp cgt;
	time_t current_time;

	datum datum_value;
	datum key_data;
	datum return_data;

	char **list = NULL;

	int MAXAGE = atoi( m->ibmdb2cachelifetime );

	GDBM_FILE gdbm;

	double time_diff;

	sprintf( ibmdb2grpcachefile, "%s.grp", m->ibmdb2cachefile );

	gdbm = gdbm_open( ibmdb2grpcachefile, 0, GDBM_WRCREAT, 00664, NULL );

	if( gdbm != NULL )
	{
		datum_value = gdbm_fetch( gdbm, datum_user );

		if( datum_value.dptr != NULL )
		{
			if( datum_value.dsize != sizeof(cgt) )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "we found our user in the cache but with corrupted record: %s \n", my_user);
				LOG_ERROR( errmsg );
				gdbm_close( gdbm );

				return NULL;
			}
			else
			{
				memcpy((void *)&cgt, datum_value.dptr, datum_value.dsize);

				if( !(time(&(current_time))) )
				{
					errmsg[0] = '\0';
					sprintf( errmsg, "unable to determine current time (read group cache)");
					LOG_ERROR( errmsg );
					gdbm_close( gdbm );

					return NULL;
				}

				time_diff = difftime( current_time, cgt.timestamp );

				i = 0;

				numgrps = cgt.numgrps;

				if( MAXAGE < time_diff )
				{
					errmsg[0] = '\0';
					sprintf( errmsg, "cached group information for user [%s] toooo old", my_user);
					LOG_DBG( errmsg );
					gdbm_close( gdbm );

					return NULL;
				}

				/* Build the list to return */

				list = (char **) malloc(sizeof(char *) * (numgrps+1));

				for( i = 0; i < numgrps; i++ )
				{
					key_data.dptr = NULL;
					return_data.dptr = NULL;

					username[0] = '\0';
					sprintf( username, "%s_%d", my_user, i );

					key_data.dptr = username;
					key_data.dsize = strlen(username) + 1;

					return_data = gdbm_fetch( gdbm, key_data );

					if( return_data.dptr != 0 )
					{
						list[i] = return_data.dptr;
					}
				}

				list[i] = NULL;

				/* Congratulations, we have a fresh cached entry */
				errmsg[0] = '\0';
				sprintf( errmsg, "groups for user [%s] found in cache", my_user);
				LOG_DBG( errmsg );
				gdbm_close(gdbm);

				return list;
			}
		}
		else
		{
			/* Did not find user in the group cache */
			errmsg[0] = '\0';
			sprintf( errmsg, "groups for user [%s] not found in cache", my_user);
			LOG_DBG( errmsg );
			gdbm_close( gdbm );

			return NULL;
		}
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "could not open group cachefile [%s] for reading", ibmdb2grpcachefile );
		LOG_ERROR( errmsg );

		return NULL;
	}
}

/*
 * callback from Apache to do the authentication of the user to his password
 */

static int ibmdb2_authenticate_basic_user( request_rec *r )
{
	ibmdb2_auth_config_rec *sec = (ibmdb2_auth_config_rec *)ap_get_module_config (r->per_dir_config, &ibmdb2_auth_module);
	conn_rec   *c = r->connection;
	const char *sent_pw, *real_pw;
	int        res;
    int passwords_match = 0;
	char *user;
    char errmsg[MAXERRLEN];

    if( (res = ap_get_basic_auth_pw(r, &sent_pw)) )
    {
		errmsg[0] = '\0';
		sprintf( errmsg, "ap_get_basic_auth_pw() returned [%i]; pw=[%s]\nend authenticate", res, sent_pw );
	    LOG_DBG( errmsg );

	    return res;
	}

	errmsg[0] = '\0';

#ifdef APACHE2
    user = r->user;
#else
    user = c->user;
#endif

	sprintf( errmsg, "begin authenticate for user=[%s], uri=[%s]", user, r->uri );
	LOG_DBG( errmsg );

    if( !sec->ibmdb2pwtable )             	/* not configured for ibmdb2 authorization */
    {
		LOG_DBG( "ibmdb2pwtable not set, return DECLINED\nend authenticate" );

		return DECLINED;
	}

	/* Caching */

	if( sec->ibmdb2caching )
	{
		if( real_pw = read_cache( r, user, sec ) )
		{
			if( sec->ibmdb2NoPasswd )
			{
				return OK;
			}

			if( sec->ibmdb2Crypted )
			{
				passwords_match = validate_pw( sent_pw, real_pw );
			}
			else
			{
				if( strcmp( sent_pw, real_pw ) == 0 )
				   passwords_match = 1;
			}
		}

		if( passwords_match )
		{
			return OK;
		}
	}

	/* Caching End */


    if( !(real_pw = get_ibmdb2_pw(r, user, sec)) )
    {
		errmsg[0] = '\0';
		sprintf( errmsg, "cannot find user [%s] in db; sent pw=[%s]", user, sent_pw );
		LOG_DBG( errmsg );

		/* user not found in database */

		if( !sec->ibmdb2Authoritative )
		{
			LOG_DBG( "ibmdb2Authoritative is Off, return DECLINED\nend authenticate" );

			return DECLINED;				/* let other schemes find user */
		}

		errmsg[0] = '\0';
		sprintf( errmsg, "user [%s] not found; uri=[%s]", user, r->uri );
		LOG_DBG( errmsg );

		ap_note_basic_auth_failure(r);

#ifdef APACHE2
    	return HTTP_UNAUTHORIZED;
#else
		return AUTH_REQUIRED;
#endif
	}

	/* if we don't require password, just return ok since they exist */
	if( sec->ibmdb2NoPasswd )
	{
		return OK;
	}

	/* validate the password */

	if( sec->ibmdb2Crypted )
	{
		passwords_match = validate_pw( sent_pw, real_pw );
	}
	else
	{
		if( strcmp( sent_pw, real_pw ) == 0 )
		   passwords_match = 1;
	}

	if( passwords_match )
	{
		if( sec->ibmdb2caching )			/* Caching */
		{
			write_cache( r, user, real_pw, sec );
		}

		return OK;
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "user=[%s] - password mismatch; uri=[%s]", user, r->uri );
		LOG_ERROR( errmsg );

		ap_note_basic_auth_failure(r);

#ifdef APACHE2
	    return HTTP_UNAUTHORIZED;
#else
		return AUTH_REQUIRED;
#endif
	}
}

/*
 * check if user is member of at least one of the necessary group(s)
 */

static int ibmdb2_check_auth( request_rec *r )
{
	ibmdb2_auth_config_rec *sec = (ibmdb2_auth_config_rec *)ap_get_module_config(r->per_dir_config, &ibmdb2_auth_module);

	char errmsg[MAXERRLEN];

#ifdef APACHE2
	char *user = r->user;
#else
	char *user = r->connection->user;
#endif

	int method = r->method_number;

#ifdef APACHE2
	const apr_array_header_t *reqs_arr = ap_requires(r);
#else
	const array_header *reqs_arr = ap_requires(r);
#endif

	require_line *reqs = reqs_arr ? (require_line *)reqs_arr->elts : NULL;

	register int x;
	char **groups = NULL;

	if( !sec->ibmdb2GroupField )
	{
		return DECLINED; 					/* not doing groups here */
	}
	if( !reqs_arr )
	{
		return DECLINED; 					/* no "require" line in access config */
	}

	/* if the group table is not specified, use the same as for password */

	if( !sec->ibmdb2grptable )
	{
		sec->ibmdb2grptable = sec->ibmdb2pwtable;
	}

	for( x = 0; x < reqs_arr->nelts; x++ )
	{
		const char *t, *want;

		if( !(reqs[x].method_mask & (1 << method)) )
		   continue;

		t = reqs[x].requirement;
		want = ap_getword(r->pool, &t, ' ');

		if( !strcmp(want,"group") )
		{
			/* check for list of groups from database only first time thru */

			if( !groups && !(groups = get_ibmdb2_groups(r, user, sec)) )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "user [%s] not in group table [%s]; uri=[%s]", user, sec->ibmdb2grptable, r->uri );
				LOG_DBG( errmsg );

				ap_note_basic_auth_failure(r);

#ifdef APACHE2
				return HTTP_UNAUTHORIZED;
#else
				return AUTH_REQUIRED;
#endif
			}

			/* loop through list of groups specified in the directives */

			while( t[0] )
			{
				int i = 0;
				want = ap_getword(r->pool, &t, ' ');

				/* compare against each group to which this user belongs */

				while( groups[i] )
				{
					/* last element is NULL */
					if( !strcmp(groups[i],want) )
					   return OK;			/* we found the user! */

					++i;
				}
			}

			errmsg[0] = '\0';
			sprintf( errmsg, "user [%s] not in right group; uri=[%s]", user, r->uri );
			LOG_ERROR( errmsg );

			ap_note_basic_auth_failure(r);

#ifdef APACHE2
			return HTTP_UNAUTHORIZED;
#else
			return AUTH_REQUIRED;
#endif
		}
	}

	return DECLINED;
}


#ifdef APACHE2
static void register_hooks(apr_pool_t *p)
{
	ap_hook_check_user_id(ibmdb2_authenticate_basic_user, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_auth_checker(ibmdb2_check_auth, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(mod_auth_ibmdb2_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
}
#endif

#ifdef APACHE2

module AP_MODULE_DECLARE_DATA ibmdb2_auth_module =
{
	STANDARD20_MODULE_STUFF,
	create_ibmdb2_auth_dir_config, 			/* dir config creater */
	NULL,                       			/* dir merger --- default is to override */
	NULL,                       			/* server config */
	NULL,                      				/* merge server config */
	ibmdb2_auth_cmds,              			/* command apr_table_t */
	register_hooks              			/* register hooks */
};

#else

module ibmdb2_auth_module =
{
	STANDARD_MODULE_STUFF,
	mod_auth_ibmdb2_init_handler,			/* initializer */
	create_ibmdb2_auth_dir_config, 			/* dir config creater */
	NULL,									/* dir merger --- default is to override */
	NULL,									/* server config */
	NULL,									/* merge server config */
	ibmdb2_auth_cmds,						/* command table */
	NULL,									/* handlers */
	NULL,									/* filename translation */
	ibmdb2_authenticate_basic_user, 		/* check_user_id */
	ibmdb2_check_auth,						/* check auth */
	NULL,									/* check access */
	NULL,									/* type_checker */
	NULL,									/* fixups */
	NULL,									/* logger */
	NULL,									/* header parser */
	NULL,									/* child_init */
	child_exit,								/* child_exit */
	NULL									/* post read-request */
};

#endif
