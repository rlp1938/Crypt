/*      writefile.c
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

#include "writefile.h"

void writefile(const char *fname, const char *fro, const char *to)
{
	// invokes fwrite()
    FILE *fpo;
    size_t siz, result;

    siz = to - fro;
    if (strcmp(fname, "-") == 0) {
		fpo = stdout;
    } else {
        fpo = fopen(fname, "w");
        if (!fpo) {
			fprintf(stderr, "File to write: %s\n", fname);
			perror("In fwrite()");
			exit(EXIT_FAILURE);
		}
    }
    result = fwrite(fro, 1, siz, fpo);
    if (result != siz) {
        fprintf(stderr, "Size discrepancy in fwrite: %s %zu, %zu",
                fname, siz, result);
        perror(fname);  // might produce something useful.
        exit(EXIT_FAILURE);
    }
    if (strcmp(fname, "-") != 0) {
		fclose(fpo);
	}
} // writefile()
