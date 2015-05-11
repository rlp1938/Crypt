/*      calcsha256sum.c
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

#include "calcsha256sum.h"

char *calcsha256sum(const char *bytes, size_t len, char *sum,
					void *binresult)
{
	/* calculate sha256sum of bytes
	 * sum must be 65 bytes or more. */

	int i, hashsize;
	unsigned char hash[32];
	char *tmp;

	sum[0] = '\0';
	hashsize = 32;

	sha256_buffer(bytes, len, &hash[0]);

	tmp = &sum[0];
	for (i = 0; i < hashsize; i++) {
		sprintf(tmp, "%.2x", hash[i]);
		tmp += 2;
	}
	sum[64] = '\0';
	memcpy(binresult, (void *)hash, 32);
	return sum;
} // calcsha256sum()

