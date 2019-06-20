#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_OPENSSL)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#else
#error OpenSSL is needed to build this moudle
#endif


static const ngx_int_t ngx_http_fake_ip_default_v4mask = 24;
static const ngx_int_t ngx_http_fake_ip_default_v6mask = 48;
static const ngx_int_t ngx_http_fake_ip_default_step   = 30;

typedef struct {
    ngx_str_t secret;
    ngx_int_t v4mask;
    ngx_int_t v6mask;
    ngx_int_t step;
    in_addr_t v4mask_num;
#if (NGX_HAVE_INET6)
    struct in6_addr v6mask_num;
#endif
} ngx_http_fake_ip_conf_t;

static ngx_int_t ngx_http_fake_ip_add_variables(ngx_conf_t *cf);
static void *ngx_http_fake_ip_create_conf(ngx_conf_t *cf);
static char *ngx_http_fake_ip_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_fake_ip_conf_set_str_base64_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_http_fake_ip_check_num(ngx_conf_t *cf, void *post, void *data);

typedef struct {
    ngx_conf_post_t ngx_conf_post_t;
    ngx_int_t lo;
    ngx_int_t hi;
} ngx_conf_fake_ip_post_num_check_t;

static ngx_conf_fake_ip_post_num_check_t ngx_http_fake_ip_step_post = {
    {ngx_http_fake_ip_check_num},
    1,
    NGX_CONF_UNSET
};

static ngx_conf_fake_ip_post_num_check_t ngx_http_fake_ip_v4mask_post = {
    {ngx_http_fake_ip_check_num},
    0,
    33
};

static ngx_conf_fake_ip_post_num_check_t ngx_http_fake_ip_v6mask_post = {
    {ngx_http_fake_ip_check_num},
    0,
    129
};

static ngx_command_t ngx_http_fake_ip_commands[] = {
    
    { ngx_string("fake_ip_secret"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | 
         NGX_CONF_TAKE1,
      ngx_http_fake_ip_conf_set_str_base64_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fake_ip_conf_t, secret),
      NULL },
    
    { ngx_string("fake_ip_step"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | 
         NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fake_ip_conf_t, step),
      &ngx_http_fake_ip_step_post },

    { ngx_string("fake_ip_v4mask"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | 
         NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fake_ip_conf_t, v4mask),
      &ngx_http_fake_ip_v4mask_post },

    { ngx_string("fake_ip_v6mask"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | 
         NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fake_ip_conf_t, v6mask),
      &ngx_http_fake_ip_v6mask_post },

    ngx_null_command
};

static ngx_http_module_t ngx_http_fake_ip_module_ctx = {
    ngx_http_fake_ip_add_variables,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_fake_ip_create_conf,          /* create location configuration */
    ngx_http_fake_ip_merge_conf            /* merge location configuration */
};

ngx_module_t ngx_http_fake_ip_module = {
    NGX_MODULE_V1,
    &ngx_http_fake_ip_module_ctx,          /* module context */
    ngx_http_fake_ip_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_fake_ip_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
		    uintptr_t data){

    ngx_http_fake_ip_conf_t *fipcf;
    fipcf = ngx_http_get_module_loc_conf(r, ngx_http_fake_ip_module);

    u_char *p = ngx_pnalloc(r->pool, NGX_SOCKADDR_STRLEN);

    if (p == NULL) {
        return NGX_ERROR;
    }

    u_char digst_buf[NGX_SOCKADDRLEN + sizeof(uint32_t)];
    u_char result_addr[NGX_SOCKADDRLEN];
    size_t buf_len = 0;

    ngx_connection_t *c = r->connection;
    ngx_memcpy(result_addr, c->sockaddr, c->socklen);
    
    struct sockaddr *sa = (struct sockaddr *)&result_addr;
    switch (sa->sa_family) {
    
    case AF_INET:
        ;
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;
	ngx_memcpy(digst_buf, &sin->sin_addr, sizeof(sin->sin_addr));
	buf_len += sizeof(sin->sin_addr);
	break;

#if (NGX_HAVE_INET6)
    
    case AF_INET6:
        ;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
	if(IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)){
	    ngx_memcpy(digst_buf, &sin6->sin6_addr.s6_addr[12], sizeof(in_addr_t));
	    buf_len += sizeof(in_addr_t);
	}else{
	    ngx_memcpy(digst_buf, &sin6->sin6_addr, sizeof(sin6->sin6_addr));
	    buf_len += sizeof(sin6->sin6_addr);
	}
	break;

#endif
    }

    uint32_t now_time = htonl(ngx_time() / fipcf->step);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "fake_ip: now time is: %ui", ntohl(now_time));
    ngx_memcpy(digst_buf + buf_len, &now_time, sizeof(now_time));
    buf_len += sizeof(now_time);
    if(c->log->log_level >= NGX_LOG_DEBUG_HTTP){
        u_char __debug_buf[3 * sizeof(digst_buf) + 1];
	for(size_t i = 0; i < buf_len; i++){
	    ngx_sprintf(__debug_buf + 3 * i, "%02xd ", digst_buf[i]);
	}
	__debug_buf[3 * buf_len] = '\0';
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "fake_ip: data in buf: %s", __debug_buf);
    }
    unsigned int mac_len = 0;
    union {
        u_char buf[EVP_MAX_MD_SIZE];
	in_addr_t in;
        struct in6_addr in6;
    } digst_rslt_buf;

    HMAC(EVP_sha1(), fipcf->secret.data, fipcf->secret.len, digst_buf,
            buf_len, digst_rslt_buf.buf, &mac_len);

    if(c->log->log_level >= NGX_LOG_DEBUG_HTTP){
        u_char __debug_buf[3 * sizeof(digst_rslt_buf.buf) + 1];
	for(size_t i = 0; i < mac_len; i++){
	    ngx_sprintf(__debug_buf + 3 * i, "%02xd ", digst_rslt_buf.buf[i]);
	}
	__debug_buf[3 * mac_len] = '\0';
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "fake_ip: result mac: %s", __debug_buf);
    }

    switch (sa->sa_family) {

    case AF_INET:
        if(buf_len < sizeof(in_addr_t)){
            ngx_log_error(NGX_LOG_CRIT, c->log, 0, 
	                    "fake_ip: Length of HMAC result is %ui, %ui needed.", 
			    buf_len, sizeof(in_addr_t));
	    return NGX_ERROR;
	}
	struct sockaddr_in *sin = (struct sockaddr_in *) sa;
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "fake_ip: v4mask_num: %08xd", ntohl(fipcf->v4mask_num));
	sin->sin_addr.s_addr = htonl( 
            (ntohl(sin->sin_addr.s_addr) & ntohl(fipcf->v4mask_num)) | 
	    (ntohl(digst_rslt_buf.in) & ~ntohl(fipcf->v4mask_num)));
	break;
#if (NGX_HAVE_INET6)
    case AF_INET6:
	;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
        if(IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)){
            if(buf_len < sizeof(in_addr_t)){
                ngx_log_error(NGX_LOG_CRIT, c->log, 0, 
	                        "fake_ip: Length of HMAC result is %ui, %ui needed.", 
	    		    buf_len, sizeof(in_addr_t));
	        return NGX_ERROR;
	    }
	    in_addr_t *in_addr = (in_addr_t *)(&sin6->sin6_addr.s6_addr[12]);
	    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "fake_ip: v4mask_num: %08xd", ntohl(fipcf->v4mask_num));
	    *in_addr = htonl( 
                (ntohl(*in_addr) & ntohl(fipcf->v4mask_num)) | 
	        (ntohl(digst_rslt_buf.in) & ~ntohl(fipcf->v4mask_num)));
	} else {
            if(buf_len < sizeof(struct in6_addr)){
                ngx_log_error(NGX_LOG_CRIT, c->log, 0, 
                                "fake_ip: Length of HMAC result is %ui, %ui needed.", 
            		    buf_len, sizeof(struct in6_addr));
                return NGX_ERROR;
            }
            for (int n = 0; n < 16; n++) {
                sin6->sin6_addr.s6_addr[n] = 
                    (sin6->sin6_addr.s6_addr[n] & fipcf->v6mask_num.s6_addr[n]) |
            	(digst_rslt_buf.in6.s6_addr[n] & ~fipcf->v6mask_num.s6_addr[n]);
            }
	}
        break;
#endif	
    }
    size_t len = ngx_sock_ntop(sa, c->socklen, p, NGX_SOCKADDR_STRLEN, 0);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;
    v->len = len;

    return NGX_OK;
}

static ngx_int_t 
ngx_http_fake_ip_add_variables(ngx_conf_t *cf){
    ngx_http_variable_t *var;
    static ngx_str_t ngx_http_fake_ip_remote_addr = ngx_string("fake_remote_addr");
    var = ngx_http_add_variable(cf, &ngx_http_fake_ip_remote_addr, 0);
    if(var == NULL){
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_fake_ip_variable;

    return NGX_OK;
}

static void *ngx_http_fake_ip_create_conf(ngx_conf_t *cf){
    ngx_http_fake_ip_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fake_ip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->step = NGX_CONF_UNSET;
    conf->v4mask = NGX_CONF_UNSET_UINT;
    conf->v6mask = NGX_CONF_UNSET_UINT;

    return conf;
}
static char *ngx_http_fake_ip_merge_conf(ngx_conf_t *cf, void *parent, void *child){
    ngx_http_fake_ip_conf_t *prev = parent;
    ngx_http_fake_ip_conf_t *conf = child;
    if(conf->secret.len == 0){
        conf->secret = prev->secret;
    }
    ngx_conf_merge_value(conf->v4mask, prev->v4mask, ngx_http_fake_ip_default_v4mask);
    ngx_conf_merge_value(conf->v6mask, prev->v6mask, ngx_http_fake_ip_default_v6mask);
    ngx_conf_merge_value(conf->step, prev->step, ngx_http_fake_ip_default_step);  
    if(conf->v4mask > 32 || conf->v4mask < 0){
        return NGX_CONF_ERROR;
    }
    if(conf->v4mask){
        conf->v4mask_num = htonl((uint32_t) (0xffffffffu << (32 - conf->v4mask)));
    }else{
        conf->v4mask_num = 0;
    }
    if(conf->v6mask > 128 || conf->v6mask < 0){
        return NGX_CONF_ERROR;
    }
#if (NGX_HAVE_INET6)
    ngx_uint_t v6_shift = conf->v6mask;
    for(int i = 0; i < 16; i++){
        ngx_uint_t s = (v6_shift > 8) ? 8 : v6_shift;
	v6_shift -= s;
	conf->v6mask_num.s6_addr[i] = (u_char) (0xffu << (8 - s));
    }
#endif
    return NGX_CONF_OK;
}

static char *ngx_http_fake_ip_conf_set_str_base64_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    char *p = conf;

    ngx_str_t *field = (ngx_str_t *)(p + cmd->offset);

    if(field->data) {
        return "is duplicate";
    }

    ngx_str_t *value = (ngx_str_t *)cf->args->elts + 1;

    field->data = ngx_pnalloc(cf->pool, ngx_base64_decoded_length(value->len));
    if(field->data == NULL) {
        return NGX_CONF_ERROR;
    }

    int rc = ngx_decode_base64(field, value);

    if(rc != NGX_OK) {
        return "contains invaild base64 encoding";
    }

    if (cmd->post) {
        ngx_conf_post_t *post = cmd->post;
	return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}

static char *ngx_http_fake_ip_check_num(ngx_conf_t *cf, void *post, void *data){
    ngx_conf_fake_ip_post_num_check_t *check = (ngx_conf_fake_ip_post_num_check_t *) post;
    ngx_int_t *value = (ngx_int_t *) data;

    if(check->lo != NGX_CONF_UNSET && *value < check->lo){
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "value should not be less than %ui", check->lo);
	return NGX_CONF_ERROR;
    }
    if(check->hi != NGX_CONF_UNSET && *value >= check->hi){
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "value should be less than %ui", check->hi);
	return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}
