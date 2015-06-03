/*      readloop.c
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

#include "readloop.h"

void readloop(const char *ftoread, const char *ftowrite,
				const char *writemode, size_t chunksize,
				char * (*process)(char *data))
{
	/*
	 * Open the input and output files, determine the size of the input
	 * file, then read that input in chunksize pieces.
	 * Operate on the read in chunk using process(), write the result
	 * to the ouput file. Determine the real chunksize to read when
	 * approaching the actual file size.
	*/

	FILE *fpi, *fpo;
	size_t bytesread;
	char *buf;

	fpi = fopen(ftoread, "r");
	fpo = fopen(ftowrite, writemode);

	if (!fpi) {
		perror(ftoread);
		exit(EXIT_FAILURE);
	}
	if (!fpo) {
		perror(ftowrite);
		exit(EXIT_FAILURE);
	}
	buf = malloc(chunksize);
	while(1){
		char *retbuf;
		bytesread = fread(buf, 1, chunksize, fpi);
		if (!bytesread) break;	// if filesize an exact multiple.
		/* here insert code to callback process() */
		(void) fwrite(retbuf, 1, bytesread, fpo);
		if (bytesread < chunksize) break;
	}
	free(buf);
	fclose(fpi);
	fclose(fpo);
} // readloop()
