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
#include "calcsha256sum.h"

void *calc_nonce(void)
{
	/* gets 8 bytes from /dev/random, followed by 8 bytes from time().
	 * The odds of /dev/random returning a duplicate value in anyone's
	 * lifetime are vanishingly small but still non-zero. The use of
	 * time() ensures that the nonce will always be unique.
	 * Once calaculated, I further calculate the sha256 message digest
	 * and return the 32 byte binary form of it.
	 * */

	static char thenonce[32];
	char unused[65];
	FILE *fpi = fopen("/dev/random", "r");
	size_t ret = fread(thenonce, 1, 8, fpi);
	fclose(fpi);
	if (ret != 8) {
		fprintf(stderr,
		"Expected to gain 8 bytes from /dev/random, but got %lu\n"
				,ret);
		perror("calc_nonce()");
		exit(EXIT_FAILURE);
	}
	union {
		unsigned char chtim[8];
		time_t tim;
	} hash;
	hash.tim = time(NULL);
	(void)memcpy(thenonce+8, hash.chtim, 8);
	(void)calcsha256sum(thenonce, 16, unused, thenonce);
	unused[64] = '\0';
	return thenonce;
} // calc_nonce()
