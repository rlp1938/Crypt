
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
#include <sys/stat.h>
#include <sys/types.h>
#include "readfile.h"
#include "writefile.h"
#include "sha256.h"
#include "calc_nonce.h"

#define NAME_MAX 256

char *helpmsg = "\n\tUsage: crypt [option] infile passphrase outfile.\n"
  "\t       crypt -s file_to_shred/delete\n"
  "\n\tOptions:\n"
  "\t-h outputs this help message.\n"
  "\t-d decryption mode. Encryption is asymmetric due to the use of\n"
  "\t   an initialisation vector when encrypting.\n"
  "\t-s file_to_shred_and_delete. This function is not done "
  "automatically.\n"
  "\tNB the passphrase if it contains spaces must be quoted.\n"
  "\tA 7 word or longer passphrase is recommended.\n"
  ;

static void dohelp(int forced);
static void encrypt(const char *outfile, const char *pw, char *from,
					char *to, int decrypting);
static char *calcsha256sum(const char *bytes, size_t len, char *sum);

int main(int argc, char **argv)
{
	int opt;
	int decrypt = 0;
	int totmp = 0;
	char *tmpdir = NULL;

	while((opt = getopt(argc, argv, ":hds:t:")) != -1) {
		switch(opt){
		fdata fdat;
		char wrk[NAME_MAX];
		case 'h':
			dohelp(0);
		break;
		case 'd': // decryption mode
		decrypt = 1;
		break;
		case 't': // write output file to a sub dir in /tmp/
		totmp = 1;
		strcpy(wrk, "/tmp/");
		strcat(wrk, optarg);
		strcat(wrk, "/");
		tmpdir = strdup(wrk);
		break;
		case 's': // shred and unlink named file
		/* I doubt that track to adjacent track leakage is an issue for
		 * drives >= 500 gigs but I will try to be safe anyway.
		*/
		fdat = readfile(optarg, 0, 1);
		char c = 85;	// 01010101
		memset(fdat.from, c, fdat.to - fdat.from);
		writefile(optarg, fdat.from, fdat.to, "w");
		sync();
		sleep(4);	// ensure that this gets written to rotating media?
		c = 170;	// 10101010
		memset(fdat.from, c, fdat.to - fdat.from);
		writefile(optarg, fdat.from, fdat.to, "w");
		sync();
		sleep(4);	// ensure that this gets written to rotating media?
		c = 0;
		memset(fdat.from, c, fdat.to - fdat.from);
		writefile(optarg, fdat.from, fdat.to, "w");
		sync();
		unlink(optarg);
		exit(EXIT_SUCCESS);
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

	char *outfile;
	if (totmp) {
		char wrk[NAME_MAX];
		strcpy(wrk, tmpdir);	// The trailing '/' is there.
		// now create the non-existent dir
		(void)mkdir(wrk, 0775);
		strcat(wrk, argv[optind]);
		outfile = strdup(wrk);
		free(tmpdir);
	} else {
		outfile = strdup(argv[optind]);
	}

	// Encryption / decryption is no longer symmetric because I have
	// added an IV, a nonce based on 16 bytes from calc_nonce(). When
	// encrypting the nonce will be created, when decrypting it will be
	// read from the encrypted file.

	char *compoundpw = malloc(strlen(pw)+ 17);	// strlen(nonce) == 16
	if(decrypt) {
		strncpy(compoundpw, fdat.from, 16);
		compoundpw[16] = '\0';
	} else {
		char *np = calc_nonce();
		writefile(outfile, np, np+16, "w");
		strcpy(compoundpw, np);
	}
	strcat(compoundpw, pw);

	// The actual encryption
	encrypt(outfile, compoundpw, fdat.from, fdat.to, decrypt);
	free(compoundpw);

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

void encrypt(const char *outfile, const char *pw, char *from, char *to,
			int decrypting)
{
	/*
	 * 1. Starts by taking the sha256sum of the passphrase, pw.
	 * 2. Encrypts the first 64 bytes of the data beginning at from.
	 * 3. Then it generates a sha256sum of the used sum and encrypts
	 * another 64 bytes.
	 * 4. Repeats until done.
	*/

	/* Now using a nonce which occupies the first 16 bytes of an
	 * encrypted file and is itself not encrypted. */

	char *writefrom, *writemode;

	char sum1[65], sum2[65];
	char *old, *current;

	old = &sum1[0];
	current = &sum2[0];

	if(decrypting) {
		writefrom = from + 16;	// don't write the nonce.
		writemode = "w";
	} else {
		writefrom = from;	// the nonce has already been written,
		writemode = "a";	// so append the encrypted data.
	}

	// pw may be any length subject only to available memory.
	(void)calcsha256sum(pw, strlen(pw), current);
	char *cp = writefrom;
	char *kp = &current[0];

	while(1) {
		size_t i;
		for(i=0; i<64; i++){
			*cp ^= *kp;
			kp++;
			cp++;
			if (cp > to) goto writeresult;	// the only exit point
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

writeresult:
	// encrypted or decrypted, write it all out.
	writefile(outfile, writefrom, to, writemode);

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
