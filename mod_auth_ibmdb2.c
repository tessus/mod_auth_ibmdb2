/*
  +----------------------------------------------------------------------+
  | mod_auth_ibmdb2: authentication using an IBM DB2 database            |
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

#define MODULE "mod_auth_ibmdb2"

#define PCALLOC apr_pcalloc
#define SNPRINTF apr_snprintf
#define PSTRDUP apr_pstrdup

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "sqlcli1.h"

#include "apr_env.h"
#include "apr.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "apr_strings.h"

#include "mod_auth_ibmdb2.h"				// structures, defines, globals
#include "caching.h"						// functions for caching mechanism

#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>

module AP_MODULE_DECLARE_DATA ibmdb2_auth_module;

/*
	Callback to close ibmdb2 handle when necessary. Also called when a
	child httpd process is terminated.
*/

/* {{{ static apr_status_t mod_auth_ibmdb2_cleanup(void *notused)
*/
static apr_status_t mod_auth_ibmdb2_cleanup(void *notused)
{
	SQLDisconnect( hdbc );                 	// disconnect the database connection
	SQLFreeHandle( SQL_HANDLE_DBC, hdbc ); 	// free the connection handle
	SQLFreeHandle( SQL_HANDLE_ENV, henv );  // free the environment handle
	
	return APR_SUCCESS;
}
/* }}} */

/*
	empty function necessary because register_cleanup requires it as one
	of its parameters
*/

/* {{{ static apr_status_t mod_auth_ibmdb2_cleanup_child(void *notused)
*/
static apr_status_t mod_auth_ibmdb2_cleanup_child(void *notused)
{
	/* nothing */
    return 0;
}
/* }}} */

/* {{{ int validate_pw( const char *sent, const char *real )
*/
int validate_pw( const char *sent, const char *real )
{
	unsigned int i = 0;
	char md5str[33];
	unsigned char digest[APR_MD5_DIGESTSIZE];
	apr_md5_ctx_t context;
	char *r;
	apr_status_t status;
	
	if( strlen( real ) == 32 )
	{
		md5str[0] = '\0';

		apr_md5_init( &context );
		apr_md5_update( &context, sent, strlen(sent) );
		apr_md5_final( digest, &context );
		for( i = 0, r = md5str; i < 16; i++, r += 2 ) 
		{
			sprintf( r, "%02x", digest[i] );
		}
		*r = '\0';
		
		if( apr_strnatcmp( real, md5str ) == 0 )
			return TRUE;
		else
			return FALSE;
	}
	
	status = apr_password_validate( sent, real );

	if( status == APR_SUCCESS )
	   return TRUE;
	else
	   return FALSE;
}
/* }}} */

//	function to check the environment/connection handle and to return the sqlca structure

/* {{{ sqlerr_t get_handle_err( SQLSMALLINT htype, SQLHANDLE handle, SQLRETURN rc )
*/
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
/* }}} */

//	function to check the statement handle and to return the sqlca structure

/* {{{ sqlerr_t get_stmt_err( SQLHANDLE stmt, SQLRETURN rc )
*/
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
/* }}} */

/*
	open connection to DB server if necessary.  Return TRUE if connection
	is good, FALSE if not able to connect.  If false returned, reason
	for failure has been logged to error_log file already.
*/

/* {{{ SQLRETURN ibmdb2_connect( request_rec *r, ibmdb2_auth_config_rec *m )
*/
SQLRETURN ibmdb2_connect( request_rec *r, ibmdb2_auth_config_rec *m )
{
	char errmsg[MAXERRLEN];
	char *db  = NULL;
	char *uid = NULL;
	char *pwd = NULL;
	sqlerr_t sqlerr;
	SQLRETURN   sqlrc = SQL_SUCCESS;
	SQLINTEGER  dead_conn = SQL_CD_TRUE; 	// initialize to 'conn is dead'

	// test the database connection
	sqlrc = SQLGetConnectAttr( hdbc, SQL_ATTR_CONNECTION_DEAD, &dead_conn, 0, NULL ) ;

	if( dead_conn == SQL_CD_FALSE )			// then the connection is alive
	{
		LOG_DBG( "  DB connection is alive; re-using" );
		return SQL_SUCCESS;
	}
	else 									// connection is dead or not yet existent
	{
		LOG_DBG( "  DB connection is dead or nonexistent; create connection" );
	}

	LOG_DBG( "  allocate an environment handle" );

	// allocate an environment handle

	sqlrc = SQLAllocHandle( SQL_HANDLE_ENV, SQL_NULL_HANDLE, &henv );
	
	if( sqlrc != SQL_SUCCESS )
	{
		sqlerr = get_handle_err( SQL_HANDLE_ENV, henv, sqlrc );
		LOG_ERROR( "IBMDB2 error: cannot allocate an environment handle" );
		LOG_DBG( sqlerr.msg );
		return( SQL_ERROR );
	}

	// allocate a connection handle

	sqlrc = SQLAllocHandle( SQL_HANDLE_DBC, henv, &hdbc );
	
	if( sqlrc != SQL_SUCCESS )
	{
		sqlerr = get_handle_err( SQL_HANDLE_ENV, henv, sqlrc );
		LOG_ERROR( "IBMDB2 error: cannot allocate a connection handle" );
		LOG_DBG( sqlerr.msg );
		return( SQL_ERROR );
	}
	
	// Set AUTOCOMMIT ON (all we are doing are SELECTs)

	if( SQLSetConnectAttr( hdbc, SQL_ATTR_AUTOCOMMIT, ( void * ) SQL_AUTOCOMMIT_ON, SQL_NTS ) != SQL_SUCCESS )
	{
		LOG_ERROR( "IBMDB2 error: cannot set autocommit on" );
		return( SQL_ERROR );
	}

	// make the database connection

	uid = m->ibmdb2user;
	pwd = m->ibmdb2passwd;
	db  = m->ibmdb2DB;
	
	sqlrc = SQLConnect( hdbc, db, SQL_NTS, uid, SQL_NTS, pwd, SQL_NTS );
	
	if( sqlrc != SQL_SUCCESS )
	{
		sqlerr = get_handle_err( SQL_HANDLE_DBC, hdbc, sqlrc );
		sprintf( errmsg, "IBMDB2 error: cannot connect to %s", db );
		LOG_ERROR( errmsg );
		LOG_DBG( sqlerr.msg );
		SQLDisconnect( hdbc );
		SQLFreeHandle( SQL_HANDLE_DBC, hdbc );
		return( SQL_ERROR );
	}

	// ELSE: connection was successful

	// make sure dbconn is closed at end of request if specified

	if( !m->ibmdb2KeepAlive )				// close db connection when request done
	{
		apr_pool_cleanup_register(r->pool, (void *)NULL,
											mod_auth_ibmdb2_cleanup,
											mod_auth_ibmdb2_cleanup_child);
	}

	return SQL_SUCCESS;
}
/* }}} */

/* {{{ SQLRETURN ibmdb2_disconnect( request_rec *r, ibmdb2_auth_config_rec *m )
*/
SQLRETURN ibmdb2_disconnect( request_rec *r, ibmdb2_auth_config_rec *m )
{
	if( m->ibmdb2KeepAlive )				// if persisting dbconn, return without disconnecting
	{
		LOG_DBG( "  keepalive on; do not disconnect from database" );
		return( SQL_SUCCESS );
	}

	LOG_DBG( "  keepalive off; disconnect from database" );

	SQLDisconnect( hdbc );

	LOG_DBG( "  free connection handle" );

	// free the connection handle

	SQLFreeHandle( SQL_HANDLE_DBC, hdbc );

	LOG_DBG( "  free environment handle" );

	// free the environment handle

	SQLFreeHandle( SQL_HANDLE_ENV, henv );

	return( SQL_SUCCESS );
}
/* }}} */

/* {{{ static void *create_ibmdb2_auth_dir_config( apr_pool_t *p, char *d )
*/
static void *create_ibmdb2_auth_dir_config( apr_pool_t *p, char *d )
{
	ibmdb2_auth_config_rec *m = PCALLOC(p, sizeof(ibmdb2_auth_config_rec));

	if( !m ) return NULL;					// failure to get memory is a bad thing

	// DEFAULT values

	m->ibmdb2NameField     = "username";
	m->ibmdb2PasswordField = "password";
	m->ibmdb2GroupField    = "groupname";
	m->ibmdb2Crypted       = 1;							// passwords are encrypted
	m->ibmdb2KeepAlive     = 1;							// keep persistent connection
	m->ibmdb2Authoritative = 1;							// we are authoritative source for users
	m->ibmdb2NoPasswd      = 0;							// we require password
	m->ibmdb2caching       = 0;							// user caching is turned off
	m->ibmdb2grpcaching    = 0;							// group caching is turned off
	m->ibmdb2cachefile     = "/tmp/auth_cred_cache";	// default cachefile
	m->ibmdb2cachelifetime = "300";						// cache expires in 300 seconds (5 minutes)

	return (void *)m;
}
/* }}} */

/* {{{ static command_rec ibmdb2_auth_cmds[] =
*/
static command_rec ibmdb2_auth_cmds[] = 
{
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

	AP_INIT_TAKE1("AuthIBMDB2UserProc", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2UserProc),
	OR_AUTHCFG, "stored procedure for user authentication"),
	
	AP_INIT_TAKE1("AuthIBMDB2GroupProc", ap_set_string_slot,
	(void *) APR_XtOffsetOf(ibmdb2_auth_config_rec, ibmdb2GroupProc),
	OR_AUTHCFG, "stored procedure for group authentication"),

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
/* }}} */

/* {{{ static int mod_authnz_ibmdb2_init_handler( apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s )
*/
static int mod_auth_ibmdb2_init_handler( apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s )
{
	char *src, *tgt, *rev;
	char release[30];
	char errmsg[MAXERRLEN];
	char *env;

	src = "$Revision$";
	rev = (char*)malloc(8*sizeof(char));
	tgt = rev;

	while( *src != ':' )
		src++;
	src++; src++;

	while( *src != '$' )
		*tgt++ = *src++;
	tgt--;
	*tgt = 0;

	release[0] = '\0';
	sprintf( release, "%s/%s", MODULE, rev );
	free(rev);

	ap_add_version_component( p, release );
	
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
/* }}} */

/*
	Fetch and return password string from database for named user.
	If we are in NoPasswd mode, returns user name instead.
	If user or password not found, returns NULL
*/

/* {{{ static char *get_ibmdb2_pw( request_rec *r, const char *user, ibmdb2_auth_config_rec *m )
*/
static char *get_ibmdb2_pw( request_rec *r, const char *user, ibmdb2_auth_config_rec *m )
{
	int         rowcount = 0;

	char        errmsg[MAXERRLEN];
	int         rc = 0;
	char        query[MAX_STRING_LEN];
	char        *pw = NULL;
	sqlerr_t	sqlerr;
	SQLHANDLE   hstmt;   					// statement handle
	SQLRETURN   sqlrc = SQL_SUCCESS;

	struct
	{
		SQLINTEGER ind ;
		SQLCHAR    val[MAX_PWD_LENGTH] ;
	} passwd;								// variable to get data from the PASSWD column

    LOG_DBG( "begin get_ibmdb2_pw()" );

	// Connect to the data source

	if( ibmdb2_connect( r, m ) != SQL_SUCCESS )
	{
		LOG_DBG( "    ibmdb2_connect() cannot connect!" );

		return NULL;
	}
	
	/*
		If we are using a stored procedure, then some of the other parameters
		are irrelevant. So process the stored procedure first.
	*/
	
	if( m->ibmdb2UserProc )
	{
		// construct SQL statement
		
		SNPRINTF( query, sizeof(query)-1, "CALL %s( '%s', ? )",
			m->ibmdb2UserProc, user );
			
		sprintf( errmsg, "    statement=[%s]", query );
		LOG_DBG( errmsg );

		LOG_DBG( "    allocate a statement handle" );

		// allocate a statement handle

		sqlrc = SQLAllocHandle( SQL_HANDLE_STMT, hdbc, &hstmt ) ;

		LOG_DBG( "    prepare the statement" );

		// prepare the statement

		sqlrc = SQLPrepare( hstmt, query, SQL_NTS ) ;
		
		LOG_DBG( "    bind the parameter" );
		
		// bind the parameter
		
		sqlrc = SQLBindParameter(hstmt,
							1,
							SQL_PARAM_OUTPUT,
							SQL_C_CHAR, SQL_CHAR,
							0, 0,
							passwd.val, MAX_PWD_LENGTH,
							&passwd.ind);
		
		LOG_DBG( "    execute the statement" );

		// execute the statement for username

		sqlrc = SQLExecute( hstmt ) ;
		
		if( sqlrc != SQL_SUCCESS )				/* check statement */
		{
			sqlerr = get_stmt_err( hstmt, sqlrc );
			errmsg[0] = '\0';

			switch( sqlerr.code )
			{
				case -440:						// stored procedure does not exist
				   sprintf( errmsg, "stored procedure [%s] does not exist", m->ibmdb2UserProc );
				   LOG_ERROR( errmsg );
				   LOG_DBG( sqlerr.msg );
				   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
				   ibmdb2_disconnect( r, m ) ;
				   return NULL;
				   break;
				case -551:						// no privilege to execute stored procedure
				   sprintf( errmsg, "user [%s] does not have the privilege to execute stored procedure [%s]", m->ibmdb2user, m->ibmdb2UserProc );
				   LOG_ERROR( errmsg );
				   LOG_DBG( sqlerr.msg );
				   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
				   ibmdb2_disconnect( r, m ) ;
				   return NULL;
				   break;
				case 100:						// no data was returned (warning, no error)
				   LOG_DBG( "    stored procedure returned no data!" );
				   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
				   ibmdb2_disconnect( r, m ) ;
				   return NULL;
				   break;
				default:
				   LOG_ERROR( "IBMDB2 error: statement cannot be processed" );
				   LOG_DBG( sqlerr.msg );
				   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
				   ibmdb2_disconnect( r, m ) ;
				   return NULL;
				   break;
			}
		}
		
		if( m->ibmdb2NoPasswd )
		{
			if( strcmp( passwd.val, user ) != 0 )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "    stored procedure did not return username=[%s]", user );
				LOG_DBG( errmsg );
				return NULL;
			}
		}
		
		if( passwd.ind > 0 )
		{
			errmsg[0] = '\0';
			if( m->ibmdb2NoPasswd )
				sprintf( errmsg, "    user from database=[%s]", passwd.val );
			else
				sprintf( errmsg, "    password from database=[%s]", passwd.val );
			LOG_DBG( errmsg );
		}
				
		LOG_DBG( "    free statement handle" );

		// free the statement handle

		sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;

		// disconnect from the data source

		ibmdb2_disconnect( r, m ) ;

		if( passwd.ind > 0 )
		{
			LOG_DBG( "end get_ibmdb2_pw()" );
			pw = (char *)PSTRDUP(r->pool, passwd.val);
			return pw;
		}
		else									// if continue handler was defined in SP
		{
			LOG_DBG( "    stored procedure returned no data!" );
			LOG_DBG( "end get_ibmdb2_pw()" );
			return NULL;
		}
	}

	/*
		If we are not checking for passwords, there may not be a password field
		in the database.  We just look up the name field value in this case
		since it is guaranteed to exist.
	*/

	if( m->ibmdb2NoPasswd )
	{
		m->ibmdb2PasswordField = m->ibmdb2NameField;
	}

	// construct SQL query

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

	// allocate a statement handle

	sqlrc = SQLAllocHandle( SQL_HANDLE_STMT, hdbc, &hstmt ) ;

	LOG_DBG( "    prepare the statement" );

	// prepare the statement

	sqlrc = SQLPrepare( hstmt, query, SQL_NTS ) ;

	/* Maybe implemented later - later binding of username

	errmsg[0] = '\0';
	sprintf( errmsg, "bind username '%s' to the statement", user );
	LOG_DBG( errmsg );

	sqlrc = SQLBindParameter(hstmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR,
								SQL_VARCHAR, MAX_UID_LENGTH, 0, user, MAX_UID_LENGTH, NULL);

	*/

	LOG_DBG( "    execute the statement" );

	// execute the statement for username

	sqlrc = SQLExecute( hstmt ) ;

	if( sqlrc != SQL_SUCCESS )				/* check statement */
	{
		sqlerr = get_stmt_err( hstmt, sqlrc );

		errmsg[0] = '\0';

		switch( sqlerr.code )
		{
			case -204:						// the table does not exist
			   sprintf( errmsg, "table [%s] does not exist", m->ibmdb2pwtable );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -206:						// the column does not exist
			   sprintf( errmsg, "column [%s] or [%s] does not exist (or both)", m->ibmdb2PasswordField, m->ibmdb2NameField );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -551:						// no privilege to access table
			   sprintf( errmsg, "user [%s] does not have the privilege to access table [%s]", m->ibmdb2user, m->ibmdb2pwtable );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -10:						// syntax error in user condition [string delimiter]
			case -104:						// syntax error in user condition [unexpected token]
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
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
		}
	}

	LOG_DBG( "    fetch each row, and display" );

	// fetch each row, and display

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

	// free the statement handle

	sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;

	// disconnect from the data source

	ibmdb2_disconnect( r, m ) ;

	LOG_DBG( "end get_ibmdb2_pw()" );

	if( rowcount > 1 )
	{
		LOG_ERROR( "query returns more than 1 row -> ooops (forgot pk on username?)" );
		return NULL;
	}

	if( rowcount == 0 )
		return NULL;

	pw = (char *)PSTRDUP(r->pool, passwd.val);
	return pw;

}
/* }}} */

/*
	get list of groups from database.  Returns array of pointers to strings
	the last of which is NULL.  returns NULL pointer if user is not member
	of any groups.
*/

/* {{{ static char **get_ibmdb2_groups( request_rec *r, char *user, ibmdb2_auth_config_rec *m )
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
	SQLHANDLE   hstmt;   					// statement handle
	SQLRETURN   sqlrc = SQL_SUCCESS;

	struct {
		SQLINTEGER ind ;
		SQLCHAR    val[MAX_PWD_LENGTH] ;
	} group;								// variable to get data from the GROUPNAME column

	typedef struct element
	{
		char data[MAX_GRP_LENGTH];
		struct element *next;
	} linkedlist_t;

	linkedlist_t *element, *first;

	// read group cache

	if( m->ibmdb2grpcaching )
	{
		cachelist = read_group_cache( r, user, m );

		if( cachelist != NULL )
		{
			return cachelist;
		}
	}

    LOG_DBG( "begin get_ibmdb2_groups()" );

	if( ibmdb2_connect( r, m ) != SQL_SUCCESS )
	{
		LOG_DBG( "   ibmdb2_connect() cannot connect!" );

		return NULL;
	}

	// construct SQL query

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
	
	if( m->ibmdb2GroupProc )
	{
		query[0] = '\0';
		SNPRINTF( query, sizeof(query)-1, "CALL %s( '%s' )",
			m->ibmdb2GroupProc, user );
	}

	errmsg[0] = '\0';
	if( m->ibmdb2GroupProc )
		sprintf( errmsg, "    statement=[%s]", query );
	else
		sprintf( errmsg, "    query=[%s]", query );
	LOG_DBG( errmsg );

	LOG_DBG( "    allocate a statement handle" );

	// allocate a statement handle

	sqlrc = SQLAllocHandle( SQL_HANDLE_STMT, hdbc, &hstmt ) ;

	LOG_DBG( "    prepare the statement" );

	// prepare the statement

	sqlrc = SQLPrepare( hstmt, query, SQL_NTS ) ;

	/* Maybe implemented later - later binding of username

	errmsg[0] = '\0';
	sprintf( errmsg, "bind username '%s' to the statement", user );
	LOG_DBG( errmsg );

	sqlrc = SQLBindParameter(hstmt, 1, SQL_PARAM_INPUT, SQL_C_CHAR,
								SQL_VARCHAR, MAX_UID_LENGTH, 0, user, MAX_UID_LENGTH, NULL);

	*/

	LOG_DBG( "    execute the statement" );

	// execute the statement for username

	sqlrc = SQLExecute( hstmt ) ;

	if( sqlrc != SQL_SUCCESS )				// check statement
	{
		sqlerr = get_stmt_err( hstmt, sqlrc );

		errmsg[0] = '\0';

		switch( sqlerr.code )
		{
			case -204:						// the table does not exist
			   sprintf( errmsg, "table [%s] does not exist", m->ibmdb2grptable );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -206:						// the column does not exist
			   sprintf( errmsg, "column [%s] or [%s] does not exist (or both)", m->ibmdb2GroupField, m->ibmdb2NameField );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -551:						// no privilege to access table or to execute stored procedure
			   if( m->ibmdb2GroupProc )
			   {
			       sprintf( errmsg, "user [%s] does not have the privilege to execute stored procedure [%s]", m->ibmdb2user, m->ibmdb2GroupProc );
			   }
			   else
			   {
			       sprintf( errmsg, "user [%s] does not have the privilege to access table [%s]", m->ibmdb2user, m->ibmdb2grptable );
			   }
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -10:						// syntax error in group condition [string delimiter]
			case -104:						// syntax error in group condition [unexpected token]
			   sprintf( errmsg, "syntax error in group condition [%s]", m->ibmdb2GroupCondition );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			case -440:						// stored procedure does not exist
			   sprintf( errmsg, "stored procedure [%s] does not exist", m->ibmdb2UserProc );
			   LOG_ERROR( errmsg );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
			default:
			   LOG_ERROR( "IBMDB2 error: statement cannot be processed" );
			   LOG_DBG( sqlerr.msg );
			   sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;
			   ibmdb2_disconnect( r, m ) ;
			   return NULL;
			   break;
		}
	}

	LOG_DBG( "    fetch each row, and display" );

	// fetch each row, and display

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
		// Building linked list

		element->next = NULL;

		while( sqlrc != SQL_NO_DATA_FOUND )
		{
			rowcount++;						// record counter

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

	// free the statement handle

	sqlrc = SQLFreeHandle( SQL_HANDLE_STMT, hstmt ) ;

	// disconnect from the data source

	ibmdb2_disconnect( r, m ) ;

	LOG_DBG( "end get_ibmdb2_groups()" );

	// Building list to be returned

	numgrps = 0;

	list = (char **) PCALLOC(r->pool, sizeof(char *) * (rowcount+1));

	element = first;

	while( element->next != NULL )
	{
		if( element->data )
			list[numgrps] = (char *) PSTRDUP(r->pool, element->data);
		else
			list[numgrps] = "";				// if no data, make it empty, not NULL

		numgrps++;
		element=element->next;
	}

	list[numgrps] = NULL;           		// last element in array is NULL

	// Free memory of linked list

	element = first;

	while( first->next != NULL )
	{
		first = element->next;
		free(element);
		element=first;
	}

	free(first);

	// End of freeing memory of linked list

	// write group cache

	if( m->ibmdb2grpcaching )
	{
		write_group_cache( r, user, (const char**)list, m );
	}

	// Returning list

	return list;
}
/* }}} */

//	callback from Apache to do the authentication of the user to his password

/* {{{ static int ibmdb2_authenticate_basic_user( request_rec *r )
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
		sprintf( errmsg, "ap_get_basic_auth_pw() returned [%i]; pw=[%s]", res, sent_pw );
	    LOG_DBG( errmsg );
	    LOG_DBG( "end authenticate" );

	    return res;
	}

	errmsg[0] = '\0';

    user = r->user;

	sprintf( errmsg, "begin authenticate for user=[%s], uri=[%s]", user, r->uri );
	LOG_DBG( errmsg );
	
	// not configured for ibmdb2 authorization

    if( !sec->ibmdb2pwtable && !sec->ibmdb2UserProc )
    {
		LOG_DBG( "ibmdb2pwtable not set, return DECLINED" );
		LOG_DBG( "end authenticate" );

		return DECLINED;
	}

	// Caching

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

	// Caching End

    if( !(real_pw = get_ibmdb2_pw(r, user, sec)) )
    {
		errmsg[0] = '\0';
		sprintf( errmsg, "cannot find user [%s] in db; sent pw=[%s]", user, sent_pw );
		LOG_DBG( errmsg );

		// user not found in database

		if( !sec->ibmdb2Authoritative )
		{
			LOG_DBG( "ibmdb2Authoritative is Off, return DECLINED" );
			LOG_DBG( "end authenticate" );

			return DECLINED;				// let other schemes find user
		}

		errmsg[0] = '\0';
		sprintf( errmsg, "user [%s] not found; uri=[%s]", user, r->uri );
		LOG_DBG( errmsg );

		ap_note_basic_auth_failure(r);

    	return HTTP_UNAUTHORIZED;
	}

	// if we don't require password, just return ok since they exist
	if( sec->ibmdb2NoPasswd )
	{
		return OK;
	}

	// validate the password

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
		if( sec->ibmdb2caching )			// Caching
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

	    return HTTP_UNAUTHORIZED;
	}
}
/* }}} */

//	check if user is member of at least one of the necessary group(s)

/* {{{ static int ibmdb2_check_auth( request_rec *r )
*/
static int ibmdb2_check_auth( request_rec *r )
{
	ibmdb2_auth_config_rec *sec = (ibmdb2_auth_config_rec *)ap_get_module_config(r->per_dir_config, &ibmdb2_auth_module);

	char errmsg[MAXERRLEN];

	char *user = r->user;

	int method = r->method_number;

	const apr_array_header_t *reqs_arr = ap_requires(r);

	require_line *reqs = reqs_arr ? (require_line *)reqs_arr->elts : NULL;

	register int x;
	char **groups = NULL;

	if( !sec->ibmdb2GroupField )
	{
		return DECLINED; 					// not doing groups here
	}
	if( !reqs_arr )
	{
		return DECLINED; 					// no "require" line in access config
	}

	// if the group table is not specified, use the same as for password

	if( !sec->ibmdb2grptable && !sec->ibmdb2UserProc )
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
			// check for list of groups from database only first time thru

			if( !groups && !(groups = get_ibmdb2_groups(r, user, sec)) )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "user [%s] not in group table [%s]; uri=[%s]", user, sec->ibmdb2grptable, r->uri );
				LOG_DBG( errmsg );

				ap_note_basic_auth_failure(r);

				return HTTP_UNAUTHORIZED;
			}

			// loop through list of groups specified in the directives

			while( t[0] )
			{
				int i = 0;
				want = ap_getword(r->pool, &t, ' ');

				// compare against each group to which this user belongs

				while( groups[i] )
				{
					// last element is NULL 
					if( !strcmp(groups[i],want) )
					   return OK;			// we found the user!

					++i;
				}
			}

			errmsg[0] = '\0';
			sprintf( errmsg, "user [%s] not in right group; uri=[%s]", user, r->uri );
			LOG_ERROR( errmsg );

			ap_note_basic_auth_failure(r);

			return HTTP_UNAUTHORIZED;
		}
	}

	return DECLINED;
}
/* }}} */

/* {{{ static void register_hooks(apr_pool_t *p)
*/
static void register_hooks(apr_pool_t *p)
{
	ap_hook_check_user_id(ibmdb2_authenticate_basic_user, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_auth_checker(ibmdb2_check_auth, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(mod_auth_ibmdb2_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
}
/* }}} */

/* {{{ module AP_MODULE_DECLARE_DATA ibmdb2_auth_module =
*/
module AP_MODULE_DECLARE_DATA ibmdb2_auth_module =
{
	STANDARD20_MODULE_STUFF,
	create_ibmdb2_auth_dir_config,			// dir config creater
	NULL,									// dir merger --- default is to override
	NULL,									// server config
	NULL,									// merge server config
	ibmdb2_auth_cmds,						// command apr_table_t
	register_hooks							// register hooks
};
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
