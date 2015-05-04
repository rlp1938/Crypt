/*      calc_nonce.c
 *
 *	Copyright 2011 Bob Parker <rlp1938@gmail.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *	MA 02110-1301, USA.
*/

#include "calc_nonce.h"

char *calc_nonce(void)
{
	/* return a 16 byte ascii string calculated from now().*/
	union {
		time_t now;
		unsigned char ch[8];
	} hash;

	static char thenonce[17];
	int i;
	char *cp = &thenonce[0];
	hash.now = time(NULL);
	for(i=0; i<8; i++) {
		sprintf(cp, "%.2x", hash.ch[i]);
		cp += 2;
	}
	thenonce[16] = '\0';
	return thenonce;
} // calc_nonce()
