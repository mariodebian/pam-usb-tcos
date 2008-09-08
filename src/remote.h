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

#ifndef PUSB_REMOTE_H_
# define PUSB_REMOTE_H_

int pusb_remote_login(t_pusb_options *opts, const char *user);
int pusb_remote_auth(t_pusb_options *opts, const char *user, char *service);

char *getenv(const char *name);

#define BUFSIZE  512
#define BIGBUF  2048

#define PUSB_REMOTE_EMPTY ""
#define PUSB_NO_COOKIE "error: no cookie"
#define XMLRPC_OK "ok"
#define XMLRPC_EMPTY ""

struct ip_address {
  int data[4] ;
  int is_ip;
  char ipstr[BUFSIZE];
};

#define XMLRPC_PORT "8998"
#define XMLRPC_METHOD "tcos.pam-usb"

#endif /* !PUSB_REMOTE_H_ */
