/*
 * Copyright (c) 2003-2007 Andrea Luzzardi <scox@sig11.org>
 * Copyright (C) 2008  mariodebian at gmail
 *
 * This file is part of the pam_usb project. pam_usb is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * pam_usb is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <string.h>
/* getpid, fchown */
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "conf.h"
#include "remote.h"
#include "log.h"
#include "base64.h"

/* used to open display and get LTSPFS_TOKEN (Xorg cookie) */
#include <X11/Xlib.h>
#include <X11/Xatom.h>

/* files, dirs and user headers */
#include <sys/stat.h>
#include <pwd.h>


/* for getenv, exit, free, rand, srand */
#include <stdlib.h>


/*******************************/
#include <xmlrpc.h>
#include <xmlrpc_client.h>
/*******************************/



int die_if_fault_occurred (xmlrpc_env *env)
{
	if (env->fault_occurred) {
		log_error("XML-RPC Fault: %s (%d)\n",env->fault_string, env->fault_code);
		return (1);
	}
	return(0);
}


struct ip_address get_ip_address(struct ip_address ip)
{
	char *display;
	char tmp[BUFSIZE];

	display=getenv("DISPLAY");

	ip.data[0]=256;
	ip.data[1]=256;
	ip.data[2]=256;
	ip.data[3]=256;

	sscanf(display, "%d.%d.%d.%d:%s", &ip.data[0], &ip.data[1], &ip.data[2], &ip.data[3], tmp);
	snprintf(ip.ipstr, BUFSIZE, "%d.%d.%d.%d", ip.data[0], ip.data[1], ip.data[2], ip.data[3]);

	if ( ip.data[0] < 256 && ip.data[1] < 256 && ip.data[2] < 256 && ip.data[3] < 256) { 
		ip.is_ip=1;
	}
	else {
		ip.is_ip=0;
	}

	return ip;
}


int pusb_remote_login(t_pusb_options *opts, const char *user)
{
	struct ip_address ip;
	char *display;

	log_debug("Checking whether the caller is remote...\n");

	display=getenv("DISPLAY");
	ip=get_ip_address(ip);

	if ( ip.is_ip ) {
		log_debug("Remote authentication request from: %s\n", ip.ipstr );
		return (1);
	}

	log_error("Caller is not remote (bad) $DISPLAY=%s\n", display);
	return (0);
}

/* method inspired in ltspfs.c */

char *get_cookie(char *ipstr, char *service) {
	Display *dpy;
	Atom comm_atom, type;
	Window root;
	char *buf;
	int res, format;
	unsigned long nitems, nleft;
	

	if (!(dpy = XOpenDisplay(NULL))) {
		log_error("Cannot open X display.\n");
		return PUSB_REMOTE_CRITICAL;
	}

	root = RootWindow(dpy, DefaultScreen(dpy));
	comm_atom = XInternAtom(dpy, "LTSPFS_TOKEN", False);

	if (comm_atom == None) {
		log_error("Couldn't allocate atom\n");
		return PUSB_REMOTE_CRITICAL;
	}

	res = XGetWindowProperty(dpy, root, comm_atom, 0, 512, 0, XA_STRING,
							&type, &format, &nitems, &nleft,
							(unsigned char **)&buf);
	if (res != Success || type != XA_STRING) {
		log_error("Couldn't read LTSPFS_TOKEN atom.\n");
		return PUSB_REMOTE_EMPTY;
	}

	log_debug("        get_cookie::buf=%s\n", buf);
	XCloseDisplay(dpy);
	return buf;
}

char *xmlrpc_call(char *service, char *ipstr, char *option, char*cmdline) {
	xmlrpc_env env;
	xmlrpc_value *resultP;
	char url[512];
	char *result;
	char *cookie;
	static char xmlrpc_returned_value[BIGBUF];

	sprintf( (char*) url, "http://%s:%s/RPC2", ipstr, XMLRPC_PORT);
	log_debug("    xmlrpc_call::Trying to XMLRPC connect URL %s\n", url );

	xmlrpc_env_init(&env);
	xmlrpc_client_init2(&env, XMLRPC_CLIENT_NO_FLAGS, "pam-usb", "0.1", NULL, 0);
	if( die_if_fault_occurred(&env) )
		return PUSB_NO_COOKIE;

	cookie=get_cookie(ipstr, service);
	if ( (strcmp(option, "initusb") != 0 ) && (strcmp(cookie, PUSB_REMOTE_EMPTY) == 0) ) {
		log_error("xmlrpc_call() cookie is empty and option != initusb '%s'\n", option);
		xmlrpc_client_cleanup();
		return PUSB_NO_COOKIE;
	}

	resultP = xmlrpc_client_call(&env, url, XMLRPC_METHOD, "(ssss)", option, cmdline, cookie, ipstr);
	if( die_if_fault_occurred(&env) ) {
		xmlrpc_client_cleanup();
		return PUSB_NO_COOKIE;
	}

	log_debug("    xmlrpc_call::called method %s, option=%s\n", XMLRPC_METHOD, option);

	xmlrpc_parse_value(&env, resultP, "s", &result);
	if( die_if_fault_occurred(&env) ) {
		xmlrpc_client_cleanup();
		return PUSB_NO_COOKIE;
	}

	snprintf(xmlrpc_returned_value, BIGBUF, "%s", result);
	
	xmlrpc_DECREF(resultP);
	xmlrpc_env_clean(&env);
	xmlrpc_client_cleanup();
	
	
	
	return (xmlrpc_returned_value);
}

char *clear_string(char *data){
    /* replace ' '  with '_' */
    int i;
    for(i=0; i < strlen(data); i++) {
        if ( data[i] == ' ' ) {
            data[i] = '_';
        }
    }
    return data;
}



int need_update_pads(t_pusb_options *opts, const char *user, char *padfilename) {
	/* check if need update PADS */
	time_t		now;
	time_t		delta;
	FILE *fp=NULL;
	struct stat st;
	

	log_debug("Checking whether pads are expired or not...\n");
	if (!(fp = fopen(padfilename, "r") ) )
	{
		log_debug("Unable to open system pad, pads must be generated.\n");
		return (1);
	}
	if (fstat(fileno(fp), &st) == -1)
	{
		fclose(fp);
		return (1);
	}
	fclose(fp);

	if (time(&now) == ((time_t)-1))
	{
		log_error("Unable to fetch current time.\n");
		return (1);
	}

	delta = now - st.st_mtime;

	if (delta > opts->pad_expiration)
	{
		log_debug("Pads expired %u seconds ago, updating...\n",
				delta - opts->pad_expiration);
		return (1);
	}
	else
	{
		log_debug("Pads were generated %u seconds ago, not updating.\n",
				delta);
		return (0);
	}
}


int pusb_remote_auth(t_pusb_options *opts, const char *user, char *service)
{
	/* main auth function */
	struct ip_address ip;

	char *result;
	char padfilename[BUFSIZE];
	char remotepad[BUFSIZE];
	char device[BIGBUF];
	
	struct passwd	*user_ent = NULL;
	struct stat		sb;
	
	char base64_local[BIGBUF], base64_remote[BIGBUF];
	size_t len, elen;
	unsigned char *buf, *e;
	
	char	magic[1024];
	int i;
	FILE *fp=NULL;

	/* check for UUID */
	if ( strcmp(opts->device.volume_uuid, PUSB_REMOTE_EMPTY) == 0 ) {
		log_error("UUID is empty.\n");
		return (0);
	}

	/* get IP address based on $DISPLAY env var */
	ip=get_ip_address(ip);
	log_info("Trying to connect to XMLRPC server at %s with port %s\n", ip.ipstr, XMLRPC_PORT );
	
	/* read cookie to catch XMLRPC critical errors */
	if (strcmp ( get_cookie(ip.ipstr, service) , PUSB_REMOTE_CRITICAL) == 0 ) {
		log_error("Can't get Xorg cookie, critical error.\n");
		return(0);
	}
	
	/* Init USB, copy cookie in Xorg root window porperty (use LTSPFS_TOKEN) */
	result=xmlrpc_call(service, ip.ipstr, "initusb", "");
	log_debug("initusb result=%s\n", result);


	/* Mount USB remote UUID if found */
	result = xmlrpc_call(service, ip.ipstr, "mountusb", opts->device.volume_uuid);
	log_debug("mountusb result=%s\n", result);
	if ( strcmp(result, XMLRPC_OK) != 0 ) {
	    log_error("mount USB give error: '%s'\n",result);
	    return (0);
	}
	
	
	/* send device UUID, model, vendor serial and check if exists (with remote udevinfo) */
	sprintf( (char*) device, "UUID=%s#MODEL=%s#VENDOR=%s#SERIAL=%s", 
						clear_string(opts->device.volume_uuid), 
						clear_string(opts->device.model),
						clear_string(opts->device.vendor),
						clear_string(opts->device.serial));
	/* check if vendor, model and serial matchs */
	result = xmlrpc_call(service, ip.ipstr, "checkdevice", device);
	log_debug("checkdevice device='%s' result='%s'\n", device, result);
	
	if ( strcmp(result, XMLRPC_OK) != 0 ) {
		log_error("pusb_remote_auth() device not match: '%s'\n", result);
		return (0);
	} 


	/* file is /mnt/__UUID__/.pamusb/__USER__.__SERVERHOSTNAME__.pad */
	sprintf( (char*) remotepad, "/mnt/%s/%s/%s.%s.pad", opts->device.volume_uuid, opts->device_pad_directory , user, opts->hostname);
	log_debug("mountusb remotepad=%s\n", remotepad);
	result = xmlrpc_call(service, ip.ipstr, "getpad", remotepad);
	if ( strcmp(result, XMLRPC_EMPTY) == 0 ) {
		log_error("pusb_remote_auth() error no remote base64 PAD\n");
		return (0);
	}
	snprintf( (char*) base64_remote, BIGBUF, "%s", result);


	/* Try to read $HOME user PAD and compare it */
	if (!(user_ent = getpwnam(user)) || !(user_ent->pw_dir))
	{
		log_error("Unable to retrieve informations for user '%s'\n", user);
		return (0);
	}
	memset(padfilename, 0x00, BUFSIZE);
	snprintf( (char*) padfilename, BUFSIZE, "%s/%s", user_ent->pw_dir, opts->system_pad_directory);
	
	if (stat(padfilename, &sb) != 0)
	{
		log_error("Directory %s does not exist.\n", padfilename);
		return (0);
	}
	
	memset(padfilename, 0x00, BUFSIZE);
	snprintf( (char*) padfilename, BUFSIZE, "%s/%s/%s.pad", user_ent->pw_dir,
			opts->system_pad_directory, opts->device.name);
	
	if (stat(padfilename, &sb) != 0)
	{
		log_error("padfilename '%s' does not exist or is not readable by me.\n", padfilename);
		return (0);
	}
	
	/* read user local PAD and convert to base64 */
	log_debug("Loading '%s' user system pad '%s'...\n", user, padfilename);
	buf = readfile(padfilename, &len);
	if (buf == NULL) {
	    log_error("Can't read user pad file\n");
	    return(0);
	}
	e=base64_encode(buf, len, &elen);
	snprintf( (char*)base64_local, BIGBUF, "%s", e);
	free(e);
	free(buf);
	
	/* compare  with remote base64 PAD*/
	
	if ( strcmp(base64_local, base64_remote) != 0 ) {
	    log_error("COMPARE PAD base64_local != base64_remote\n");
	    return(0);
	}

	log_info("Compare PAD's base64_local == base64_remote\n");
	
	
	/* check if need update PADS */
	if ( need_update_pads(opts, user, padfilename) ) {
		log_info("Updating PADS.\n");
		
		srand(getpid() * time(NULL));
		for (i = 0; i < sizeof(magic); ++i)
			magic[i] = (char)rand();
			
		/* write in local $HOME */
		fp=fopen(padfilename, "w+");
		fwrite(magic, sizeof(char), sizeof(magic), fp);
		
		/* protect local file PAD */
		if (fchown(fileno(fp), user_ent->pw_uid, user_ent->pw_gid) == -1)
		{
			log_info("Unable to change owner of the pad: %s\n",
				strerror(errno));
			//return (0);
		}
		if (fchmod(fileno(fp), S_IRUSR | S_IWUSR) == -1)
		{
			log_info("Unable to change mode of the pad: %s\n",
				strerror(errno));
			//return (0);
		}
		fclose(fp);
		log_info("Local pad '%s' saved.\n", padfilename);
		
		
		/* write in remote device with XMLRPC */
		buf = readfile(padfilename, &len);
		e=base64_encode(buf, len, &elen);
		snprintf( (char*)base64_remote, BIGBUF, "%s", e);
		sprintf( (char*) remotepad, "//mnt/%s/%s/%s.%s.pad", opts->device.volume_uuid, opts->device_pad_directory , user, opts->hostname);
		result = xmlrpc_call(service, ip.ipstr, remotepad, base64_remote);
		log_debug("Remote pad '%s' saved '%s'\n", remotepad, result);
	}
	/* umount device */
	result = xmlrpc_call(service, ip.ipstr, "umountusb", opts->device.volume_uuid);
	log_debug("umount USB result='%s'\n", result);
	
	
	return (1);
	/*
	return :
		0 no auth
		1 ok
	*/
}

