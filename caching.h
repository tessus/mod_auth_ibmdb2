/*
  +----------------------------------------------------------------------+
  | caching: functions for caching mechanism                             |
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

#ifndef CACHING_H
#define CACHING_H

#include "apr_general.h"
#include "apr_dbm.h"
#include "apr_time.h"

typedef struct {
        char   password[MAX_PWD_LENGTH];
        apr_time_t timestamp;
} cached_password_timestamp;

typedef struct {
        int    numgrps;
        apr_time_t timestamp;
} cached_group_timestamp;

static int write_cache( request_rec *r, const char *user, const char *password, ibmdb2_auth_config_rec *m );
static char *read_cache( request_rec *r, const char *user, ibmdb2_auth_config_rec *m );
static int write_group_cache( request_rec *r, const char *user, const char **grplist, ibmdb2_auth_config_rec *m );
static char **read_group_cache( request_rec *r, const char *user, ibmdb2_auth_config_rec *m );

/*
	function to store the user credentials in the local cache, so that subsequent
	http requests can validate the user directly from local cache without the need
	to query the backend db2 database.
*/

/* {{{ static int write_cache( request_rec *r, const char *user, const char *password, ibmdb2_auth_config_rec *m )
*/
static int write_cache( request_rec *r, const char *user, const char *password, ibmdb2_auth_config_rec *m )
{
	apr_status_t rc;
	apr_pool_t *pool;
	apr_dbm_t *db;
	char errmsg[MAXERRLEN];
	int rc_write_cache = 0;

	char *my_user = (char *)user;
	apr_datum_t datum_user = { my_user, (strlen( my_user )+1) };

	cached_password_timestamp cpt;

	apr_datum_t datum_value;

	char *my_password = (char *)password;
	strcpy(cpt.password, my_password);

	if( !(cpt.timestamp = apr_time_now()) )
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "unable to determine current time (write cache)");
		LOG_ERROR( errmsg );
		return( 1 );
	}

	datum_value.dptr = (void *)&cpt;
	datum_value.dsize = sizeof(cpt);
	
	apr_pool_create( &pool, NULL );

	rc = apr_dbm_open(&db, m->ibmdb2cachefile, APR_DBM_RWCREATE, APR_UREAD | APR_UWRITE, pool);

	if ( rc == APR_SUCCESS )
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "storing user [%s] and pass [%s] in cache", my_user, my_password);
		LOG_DBG( errmsg );

		if( (rc = apr_dbm_store(db, datum_user, datum_value)) != APR_SUCCESS )
		{
			errmsg[0] = '\0';
			sprintf( errmsg, "unable to store user [%s] in cache", my_user);
			LOG_DBG( errmsg );
			errmsg[0] = '\0';
			apr_strerror( rc, errmsg, sizeof(errmsg) );
			LOG_DBG( errmsg );
			
			rc_write_cache = 1;
		}

		apr_dbm_close( db );
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "could not open cachefile [%s] for writing", m->ibmdb2cachefile );
		LOG_ERROR( errmsg );
		errmsg[0] = '\0';
		apr_strerror( rc, errmsg, sizeof(errmsg) );
		LOG_DBG( errmsg );
		
		rc_write_cache = 1;
	}
	
	apr_pool_destroy( pool );

	return( rc_write_cache );
}
/* }}} */

/*
	function to check in the local cache to validate user, otherwise
	we need to query the backend db2 database.
*/

/* {{{ static char *read_cache( request_rec *r, const char *user, ibmdb2_auth_config_rec *m )
*/
static char *read_cache( request_rec *r, const char *user, ibmdb2_auth_config_rec *m )
{
	apr_status_t rc;
	apr_pool_t *pool;
	apr_dbm_t *db;
	char errmsg[MAXERRLEN];

	char *my_user = (char *)user;
	apr_datum_t datum_user = { my_user, (strlen( my_user )+1) };

	cached_password_timestamp cpt;
	apr_time_t current_time;

	apr_datum_t datum_value;

	char *pw = NULL;

	int MAXAGE = atoi( m->ibmdb2cachelifetime );

	apr_time_t time_diff;
	
	apr_pool_create( &pool, NULL );

	rc = apr_dbm_open(&db, m->ibmdb2cachefile, APR_DBM_RWCREATE, APR_UREAD | APR_UWRITE, pool);

	if( rc == APR_SUCCESS )
	{
		rc = apr_dbm_fetch( db, datum_user, &datum_value );

		if( rc == APR_SUCCESS )
		{
			if( datum_value.dsize != sizeof(cpt) )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "we found our user in the cache but with corrupted record: %s \n", my_user);
				LOG_ERROR( errmsg );
				
				apr_dbm_close( db );
				apr_pool_destroy( pool );

				return NULL;
			}
			else
			{
				memcpy((void *)&cpt, datum_value.dptr, datum_value.dsize);

				if( !(current_time = apr_time_now()) )
				{
					errmsg[0] = '\0';
					sprintf( errmsg, "unable to determine current time (read cache)");
					LOG_ERROR( errmsg );
					
					apr_dbm_close( db );
					apr_pool_destroy( pool );

					return NULL;
				}

				time_diff = current_time - cpt.timestamp;

				if( apr_time_sec(time_diff) > MAXAGE )
				{
					errmsg[0] = '\0';
					sprintf( errmsg, "cached password for user [%s] is toooo old", my_user);
					LOG_DBG( errmsg );
					
					apr_dbm_close( db );
					apr_pool_destroy( pool );

					return NULL;
				}

				pw = cpt.password;

				/* Congratulations, we have a fresh cached entry */
				errmsg[0] = '\0';
				sprintf( errmsg, "user [%s] - [%s] found in cache", my_user, pw);
				LOG_DBG( errmsg );
				
				apr_dbm_close( db );
				apr_pool_destroy( pool );

				return pw;
			}
		}
		else
		{
			/* Did not find user in the cache */
			errmsg[0] = '\0';
			sprintf( errmsg, "user [%s] not found in cache", my_user);
			LOG_DBG( errmsg );
			
			apr_dbm_close( db );
			apr_pool_destroy( pool );
			
			return NULL;
		}
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "could not open cachefile [%s] for reading", m->ibmdb2cachefile );
		LOG_ERROR( errmsg );
		errmsg[0] = '\0';
		apr_strerror( rc, errmsg, sizeof(errmsg) );
		LOG_DBG( errmsg );

		apr_pool_destroy( pool );
		return NULL;
	}
}
/* }}} */

/*
	function to store the group information in the local cache, so that subsequent
	http requests can validate the groups directly from local cache without the need
	to query the backend db2 database.
*/

/* {{{ static int write_group_cache( request_rec *r, const char *user, const char **grplist, ibmdb2_auth_config_rec *m )
*/
static int write_group_cache( request_rec *r, const char *user, const char **grplist, ibmdb2_auth_config_rec *m )
{
	apr_status_t rc;
	apr_pool_t *pool;
	apr_dbm_t *db;
	char errmsg[MAXERRLEN];
	int rc_write_group_cache = 0;

	char ibmdb2grpcachefile[512];
	char username[MAX_UID_LENGTH+4];
	char groupname[MAX_GRP_LENGTH];

	int i = 0;

	char *my_user = (char *)user;
	apr_datum_t datum_user = { my_user, (strlen( my_user )+1) };

	cached_group_timestamp cgt;

	apr_datum_t datum_value;
	apr_datum_t key_data;
	apr_datum_t data_data;
	
	sprintf( ibmdb2grpcachefile, "%s.grp", m->ibmdb2cachefile );

	if( !(cgt.timestamp = apr_time_now()) )
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

	apr_pool_create( &pool, NULL );
	
	rc = apr_dbm_open(&db, ibmdb2grpcachefile, APR_DBM_RWCREATE, APR_UREAD | APR_UWRITE, pool);

	if( rc == APR_SUCCESS )
	{
		if( (rc = apr_dbm_store(db, datum_user, datum_value)) != APR_SUCCESS )
		{
			errmsg[0] = '\0';
			sprintf( errmsg, "unable to store group info for user [%s] in cache", my_user);
			LOG_DBG( errmsg );
			errmsg[0] = '\0';
			apr_strerror( rc, errmsg, sizeof(errmsg) );
			LOG_DBG( errmsg );

			apr_dbm_close( db );
			apr_pool_destroy( pool );
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

			if( (rc = apr_dbm_store(db, key_data, data_data)) != APR_SUCCESS )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "unable to store group [%s] for user [%s] in cache", grplist[i], my_user );
				LOG_DBG( errmsg );
				errmsg[0] = '\0';
				apr_strerror( rc, errmsg, sizeof(errmsg) );
				LOG_DBG( errmsg );

				apr_dbm_close( db );
				apr_pool_destroy( pool );
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

		apr_dbm_close( db );
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "could not open group cachefile [%s] for writing", ibmdb2grpcachefile );
		LOG_ERROR( errmsg );
		errmsg[0] = '\0';
		apr_strerror( rc, errmsg, sizeof(errmsg) );
		LOG_DBG( errmsg );

		rc_write_group_cache = 1;
	}
	
	apr_pool_destroy( pool );
	
	return( rc_write_group_cache );
}
/* }}} */

/*
	function to check in the local cache to check if user is in a group, otherwise
	we need to query the backend db2 database.
*/

/* {{{ static char **read_group_cache( request_rec *r, const char *user, ibmdb2_auth_config_rec *m )
*/
static char **read_group_cache( request_rec *r, const char *user, ibmdb2_auth_config_rec *m )
{
	apr_status_t rc;
	apr_pool_t *pool;
	apr_dbm_t *db;
	char errmsg[MAXERRLEN];

	char ibmdb2grpcachefile[512];
	char username[MAX_UID_LENGTH+4];

	int i = 0;

	int numgrps;

	char *my_user = (char *)user;
	apr_datum_t datum_user = { my_user, (strlen( my_user )+1) };

	cached_group_timestamp cgt;
	apr_time_t current_time;

	apr_datum_t datum_value;
	apr_datum_t key_data;
	apr_datum_t return_data;

	char **list = NULL;

	int MAXAGE = atoi( m->ibmdb2cachelifetime );

	apr_time_t time_diff;

	sprintf( ibmdb2grpcachefile, "%s.grp", m->ibmdb2cachefile );
	
	apr_pool_create( &pool, NULL );

	rc = apr_dbm_open(&db, ibmdb2grpcachefile, APR_DBM_RWCREATE, APR_UREAD | APR_UWRITE, pool);

	if( rc == APR_SUCCESS )
	{
		rc = apr_dbm_fetch( db, datum_user, &datum_value );

		if( rc == APR_SUCCESS )
		{
			if( datum_value.dsize != sizeof(cgt) )
			{
				errmsg[0] = '\0';
				sprintf( errmsg, "we found our user in the cache but with corrupted record: %s \n", my_user);
				LOG_ERROR( errmsg );
				
				apr_dbm_close( db );
				apr_pool_destroy( pool );

				return NULL;
			}
			else
			{
				memcpy((void *)&cgt, datum_value.dptr, datum_value.dsize);

				if( !(current_time = apr_time_now()) )
				{
					errmsg[0] = '\0';
					sprintf( errmsg, "unable to determine current time (read group cache)");
					LOG_ERROR( errmsg );
					
					apr_dbm_close( db );
					apr_pool_destroy( pool );

					return NULL;
				}

				time_diff = current_time - cgt.timestamp;

				i = 0;

				numgrps = cgt.numgrps;

				if( apr_time_sec(time_diff) > MAXAGE )
				{
					errmsg[0] = '\0';
					sprintf( errmsg, "cached group information for user [%s] toooo old", my_user);
					LOG_DBG( errmsg );
					
					apr_dbm_close( db );
					apr_pool_destroy( pool );

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

					rc = apr_dbm_fetch( db, key_data, &return_data );

					if( rc == APR_SUCCESS )
					{
						list[i] = return_data.dptr;
					}
				}

				list[i] = NULL;

				/* Congratulations, we have a fresh cached entry */
				errmsg[0] = '\0';
				sprintf( errmsg, "groups for user [%s] found in cache", my_user);
				LOG_DBG( errmsg );
				
				apr_dbm_close( db );
				apr_pool_destroy( pool );

				return list;
			}
		}
		else
		{
			/* Did not find user in the group cache */
			errmsg[0] = '\0';
			sprintf( errmsg, "groups for user [%s] not found in cache", my_user);
			LOG_DBG( errmsg );
			
			apr_dbm_close( db );
			apr_pool_destroy( pool );

			return NULL;
		}
	}
	else
	{
		errmsg[0] = '\0';
		sprintf( errmsg, "could not open group cachefile [%s] for reading", ibmdb2grpcachefile );
		LOG_ERROR( errmsg );
		errmsg[0] = '\0';
		apr_strerror( rc, errmsg, sizeof(errmsg) );
		LOG_DBG( errmsg );

		apr_pool_destroy( pool );
		return NULL;
	}
}
/* }}} */

#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
