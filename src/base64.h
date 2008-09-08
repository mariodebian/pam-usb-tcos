/*
 * Copyright (C) 2008  mariodebian at gmail
 *
 * Code based on WPASUPPLICANT project
 * http://hostap.epitest.fi/wpa_supplicant/
 * http://koders.com/c/fid4B33290485F0C5F2A0BEC3D0779A6DEE41C4C645.aspx
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

#ifndef PUSB_BASE64_H_
# define PUSB_BASE64_H_

unsigned char *base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len);
unsigned char *readfile(const char *name, size_t *len);

#endif /* !PUSB_BASE64_H_ */





