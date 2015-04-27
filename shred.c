/*      shred.c
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

#include "shred.h"

void shred(const char *fn)
{
	fdata fdat = readfile(fn, 0, 1);
	char *cp = fdat.from;
	while(cp < fdat.to) {
		*cp = '\0';
		cp++;
	}
	writefile(fn, fdat.from, fdat.to);
	sync();
	//unlink(fn);
}

