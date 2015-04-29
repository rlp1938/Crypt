
/*      crypt.c
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


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>
#include "readfile.h"
#include "writefile.h"
#include "sha256.h"

char *helpmsg = "\n\tUsage: crypt [option] infile passphrase outfile.\n"
  "\n\tOptions:\n"
  "\t-h outputs this help message.\n"
  "\t-D decryption mode, don't shred and unlink the infile on"
  " completion.\n"
  "\tNB the passphrase if it contains spaces must be quoted.\n"
  "\tA 7 word passprase is recommended.\n"
  ;

static void dohelp(int forced);
static void encrypt(const char *pw, char *from, char *to);
static char *calcsha256sum(const char *bytes, size_t len, char *sum);


int main(int argc, char **argv)
{
	int opt;
	int decrypt = 0;

	while((opt = getopt(argc, argv, ":hd ")) != -1) {
		switch(opt){
		case 'h':
			dohelp(0);
		break;
		case 'd': // decryption mode
		decrypt = 1;
		break;
		case ':':
			fprintf(stderr, "Option %c requires an argument\n",optopt);
			dohelp(1);
		break;
		case '?':
			fprintf(stderr, "Illegal option: %c\n",optopt);
			dohelp(1);
		break;
		} //switch()
	}//while()
	// now process the non-option arguments

	// 1.Check that argv[???] exists.
	if (!(argv[optind])) {
		fprintf(stderr, "No infile provided\n");
		dohelp(1);
	}

	// 2. read the inputfile if such exists.
	char *infilename = strdup(argv[optind]);
	fdata fdat = readfile(infilename, 0, 1);	//

	// The passphrase
	optind++;
	//
	if (!(argv[optind])) {
		fprintf(stderr, "No passphrase provided\n");
		dohelp(1);
	}
	char *pw = strdup(argv[optind]);

	// The output file.
	optind++;
	if (!(argv[optind])) {
		fprintf(stderr, "No output file provided\n");
		dohelp(1);
	}
	char *outfile = strdup(argv[optind]);

	// The actual encryption
	encrypt(pw, fdat.from, fdat.to);

	// encrypted, write the result.
	writefile(outfile, fdat.from, fdat.to);

	if (!(decrypt)) {
		// poor man's shred routine.
		memset(fdat.from, 0, fdat.to - fdat.from);
		writefile(infilename, fdat.from, fdat.to);
		unlink(infilename);
	}

	free(outfile);
	free(pw);
	free(fdat.from);
	free(infilename);
	return 0;
}//main()

void dohelp(int forced)
{
  fputs(helpmsg, stderr);
  exit(forced);
}

void encrypt(const char *pw, char *from, char *to)
{
	/*
	 * 1. Starts by taking the sha256sum of the passphrase, pw.
	 * 2. Encrypts the first 64 bytes of the data beginning at from.
	 * 3. Then it generates a sha256sum of the used sum and encrypts
	 * another 64 bytes.
	 * 4. Repeats until done.
	*/
	char sum1[65], sum2[65];
	char *old, *current;

	old = &sum1[0];
	current = &sum2[0];

	strcpy(old, pw);
	(void)calcsha256sum(old, strlen(old), current);
	char *cp = from;
	char *kp = &current[0];

	while(1) {
		size_t i;
		for(i=0; i<64; i++){
			*cp ^= *kp;
			kp++;
			cp++;
			if (cp > to) return;	// the only exit point
		}
		// now swap old and current
		{
			char *tmp = old;
			old = current;
			current = tmp;
		}
		(void)calcsha256sum(old, 64, current);
		kp = &current[0];
	}
} // encrypt()

char *calcsha256sum(const char *bytes, size_t len, char *sum)
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
	return sum;
} // calcsha256sum()
