
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
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include "readfile.h"
#include "writefile.h"
#include "sha256.h"
#include "calc_nonce.h"
#include "calcsha256sum.h"

void *memmem(const void *haystack, size_t haystacklen,
                    const void *needle, size_t needlelen);


char *helpmsg = "\n\tUsage: crypt [option] infile pass-phrase outfile.\n"
  "\t       crypt -s file_to_shred/delete\n"
  "\t       crypt -l infile pass-phrase\n"
  "\n\tOptions:\n"
  "\t-h outputs this help message.\n"
  "\t-d decryption mode. encryption is asymmetric due to the use of\n"
  "\t   an initialisation vector when encrypting.\n"
  "\t-s file_to_shred_and_delete. This function is not done "
  "automatically.\n"
  "\t-D debug mode. Writes the hex representations of the sha256sums\n"
  "\t   to stderr. If you direct stderr to a file note that the size\n"
  "\t   of that file will be double that of the source file.\n"
  "\t-l mode. Listing mode. Expect to find the objects to en/decrypt\n"
  "\t   in a formatted file. Such file is expected to be encrypted\n"
  "\t   so -d is implied.\n"
  "\t   An output file is not required, nor if specified will it be\n"
  "\t   written.\n"
  "\tNB the passphrase if it contains spaces must be quoted.\n"
  "\tA 7 word or longer passphrase is recommended.\n"
  ;
typedef struct prmstr {
	char *param;
	char *nextfrom;
} prmstr;

static void dohelp(int forced);
static void doencrypt(const char *outfile, const char *pw, char *from,
					char *to, int decrypting);
static void	processlist(char *writefrom, char *to);
			// Only needs the decrypted image.
static prmstr getparam(const char *srchfor, char *from, char *to,
						int fatal, int wantsts);
static void dosystem(const char *cmd);

static int debug, list;
static char themode;
static char *program;


int main(int argc, char **argv)
{
	int opt;
	int decrypt = 0;
	int totmp = 0;
	char *tmpdir = NULL;
	list = debug = 0;

	while((opt = getopt(argc, argv, ":hds:t:Dl:")) != -1) {
		switch(opt){
		fdata fdat;
		char wrk[NAME_MAX];
		case 'h':
			dohelp(0);
		break;
		case 'd': // decryption mode
		decrypt = 1;
		break;
		case 'D': // debugging mode
		debug = 1;
		break;
		case 'l': // listing mode, process items in a list
		decrypt = 1;	// expect the list file to be encrypted.
		list = 1;
		themode = optarg[0];
		if (!(themode == 'e' || themode == 'd')) {
			fprintf(stderr, "Illegal value for encrytion mode: %c\n",
			themode);
			exit(EXIT_FAILURE);
		}
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

	program = argv[0];	// needed sometimes

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
	char *outfile = NULL;

	// The output file.
	if (!list) {
		optind++;
		if (!(argv[optind])) {
			fprintf(stderr, "No output file provided\n");
			dohelp(1);
		}

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
	} // if(!list)

	// encryption / decryption is no longer symmetric because I have
	// added an IV, a nonce based on 16 bytes from calc_nonce(). When
	// encrypting the nonce will be created, when decrypting it will be
	// read from the encrypted file.

	char *compoundpw = malloc(strlen(pw)+ 33);	// len(nonce) == 32
	if(decrypt) {
		memcpy(compoundpw, fdat.from, 32);
	} else {
		void *np = calc_nonce();
		writefile(outfile, np, np+32, "w");
		memcpy(compoundpw, np, 32);
	}
	strcpy(compoundpw+32, pw);

	// The actual encryption
	doencrypt(outfile, compoundpw, fdat.from, fdat.to, decrypt);
	free(compoundpw);

	if (!list) free(outfile);
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

void doencrypt(const char *outfile, const char *pw, char *from, char *to,
			int decrypting)
{
	/*
	 * 1. Starts by taking the sha256sum of the passphrase, pw.
	 * 2. encrypts the first 32 bytes of the data beginning at from.
	 * 3. Then it generates a sha256sum of the used sum and encrypts
	 * another 32 bytes. NB uses the binary form of the sum not the
	 * 64 byte hex format produced for human use.
	 * 4. Repeats until done.
	*/

	/* Now using a nonce which occupies the first 32 bytes of an
	 * encrypted file and is itself not encrypted. */

	char *writefrom, *writemode;

	char sum1[65];
	char *current;
	unsigned char result[32];

	current = &sum1[0];

	if(decrypting) {
		writefrom = from + 32;	// don't write the nonce.
		writemode = "w";
	} else {
		writefrom = from;	// the nonce has already been written,
		writemode = "a";	// so append the encrypted data.
	}

	// pw may be any length subject only to available memory.
	(void)calcsha256sum(pw, strlen(pw), current, result);

	char *cp = writefrom;
	unsigned char *kp = &result[0];

	while(1) {
		if (debug) {
			// write the hex version of the sum to stderr
			fprintf(stderr, "%s\n", current);
		} // debug

		// the actual encryption.
		size_t i;
		for (i=0; i<32; i++) {
			*cp ^= *kp;
			kp++;
			cp++;
			if (cp > to) goto writeresult;	// the only exit point
		}

		// get the next sum
		(void)calcsha256sum(current, 64, current, result);
		kp = &result[0];
	}

writeresult:
	// encrypted or decrypted, write it all out.
	if (!list) {
		writefile(outfile, writefrom, to, writemode);
	} else {
		processlist(writefrom, to); // Only needs the decrypted image.
	}

} // doencrypt()

void processlist(char *writefrom, char *to)
{
	// invoke this program to process a list of objects
	char *cp;
	int incomment = 0;
	prmstr prmd;
	cp = writefrom;
	// first job, replace all commented material with ' '.
	while (cp < to) {
		switch(*cp) {
			case '#':
			incomment = 1;
			*cp = ' ';
			break;
			case '\t':
			*cp = ' ';
			break;
			case '\n':
			incomment = 0;
			break;
			default:
			if(incomment) *cp = ' ';
			break;
		}
		cp++;
	}
	cp = writefrom;
	char *ptpath;
	// See if I have a from and or to path specified
	prmd = getparam("PTPATH=", cp, to, 0, 1);
	// I'm not using nextfrom here because I will enforce no ordering
	// on these objects.
	if (prmd.param) {
		ptpath = strdup(prmd.param);
	} else {
		ptpath = NULL;	// NULL
	}
	char *etpath;
	prmd = getparam("ETPATH=", cp, to, 0, 1);
	if (prmd.param) {
		etpath = strdup(prmd.param);
	} else {
		etpath = NULL;	// NULL
	}

	cp = writefrom;	// init for while loop
	// I do use nextfrom here because I do want to enforce ordering,
	// PT, ET, then PP. Not only that ordering, the set must comprise
	// all 3 objects, else it's fatal.
	char *fmt;
	if (themode == 'd') { // protect all strings
		fmt = "%s -d '%s' '%s' '%s'";
	} else {
		fmt = "%s '%s' '%s' '%s'";
	}
	while(1) {
		char command[PATH_MAX];
		char *pt, *et, *pp, *in, *out, *inpath, *outpath;
		// PT
		prmd = getparam("PT=", cp, to, 0, 0);
		if (!prmd.param) break;	// done
		pt = strdup(prmd.param);
		// ET
		prmd = getparam("ET=", prmd.nextfrom, to, 1, 0);
		// no return if non existent.
		et = strdup(prmd.param);
		// PP
		prmd = getparam("PP=", prmd.nextfrom, to, 1, 0);
		pp = strdup(prmd.param);
		if (themode == 'd') {
			in = et;
			out = pt;
			inpath = etpath;
			outpath = ptpath;
		} else {
			in = pt;
			out = et;
			inpath = ptpath;
			outpath = etpath;
		}
		// NB *path may be NULL
		char in_name[NAME_MAX];
		char out_name[NAME_MAX];
		in_name[0] = '\0';
		out_name[0] = '\0';
		strcat(in_name, inpath);	// NULL path auto handled
		strcat(in_name, in);
		strcat(out_name, outpath);	// NULL path auto handled
		strcat(out_name, out);
		// now prepare the command
		sprintf(command, fmt, program, in_name, pp, out_name);
		// free the strdups
		free(pp);
		free(et);
		free(pt);
		// do the command
		fprintf(stdout, "%s\n", command);
		dosystem(command);
		cp = prmd.nextfrom;	// initialise for the next pass.
	}

} // processlist()

prmstr getparam(const char *srchfor, char *from, char *to, int fatal,
				int wantsts)
{
	/* Looks for text strings that begin with ??=sometext and returns
	 * sometext. It also sets nextfrom to near the end of line of the
	 * discovered parameter for the next search.
	 * fatal is set to 0 if a searched for parameter is not necessarily
	 * required. In that case a NULL * is returned if absent. If fatal
	 * is 1 the program will terminate with error message.
	 * wantsts if non zero will cause a '/' to be appended to the found
	 * text if it's not present. Ie this is for dir names.
	 * NB Real data lines must start at line 2 or after, and the file
	 * must end with '\n'.
	*/
	char srchstr[128];
	static char result[NAME_MAX];
	char line[80];
	char *bod, *eod, *eol, *cp;
	prmstr prmd;

	size_t len = strlen(srchfor) + 1;	// will prepend '\n'

	strcpy(srchstr, "\n");
	strcat(srchstr, srchfor);
	cp = memmem(from, to - from, srchstr, len);
	if(!cp) {
		if (fatal){
			fprintf(stderr, "Fatal error, could not find: %s\n",
						srchfor);
			exit(EXIT_FAILURE);
		} else {
			prmd.param = NULL;
			return prmd;
		}
	}
	bod = cp + len;	// beginning of data
	eol = memchr(bod, '\n', to - bod);
	if (!eol) {
		fprintf(stderr, "Fatal, no line end where expected\n");
		exit(EXIT_FAILURE);
	}
	memset(line, 0 ,80);
	memcpy(line, bod, eol - bod);
	eod = line + strlen(line) - 1;
	// next logic expects that commented stuff and '\t' is all ' '.
	while(*eod == ' ') eod--;
	if (wantsts && *eod != '/') {
		eod++;
		*eod = '/';
	}
	eod++;	// location of '\0'
	*eod = '\0';
	strcpy(result, line);
	prmd.param = result;
	prmd.nextfrom = eol - 2;	// next search if any may start here.
	return prmd;
} // getparam()

void dosystem(const char *cmd)
{
    const int status = system(cmd);

    if (status == -1) {
        fprintf(stderr, "System to execute: %s\n", cmd);
        exit(EXIT_FAILURE);
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        fprintf(stderr, "%s failed with non-zero exit\n", cmd);
        exit(EXIT_FAILURE);
    }
    return;
} // dosystem()
