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
static void listdecrypt(const char *pw, char *from, char *to,
						size_t ivmode);
static void	processlist(char *writefrom, char *to);
			// Only needs the decrypted image.
static prmstr getparam(const char *srchfor, char *from, char *to,
						int fatal, int wantsts);
static void dosystem(const char *cmd);
static void readwriteloop(const char *infile, const char *outfile,
					const char *pw, size_t chunksize, size_t ivsize);
//static void logthisbin(void *buf, size_t size, const char *fn);
static void shredfile(const char *fn);
static int debug, list;
static char themode;
static char *program;
static int decrypt;

int main(int argc, char **argv)
{
	int opt;
	int totmp = 0;
	char *tmpdir = NULL;
	list = debug = 0;
	decrypt = 0;
	while((opt = getopt(argc, argv, ":hds:t:Dl:")) != -1) {
		switch(opt){
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
		shredfile(optarg);
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
	char *infile = strdup(argv[optind]);

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

	// The actual encryption
	if (list) {	// in memory processing
		fdata fdat = readfile(infile, 0, 1);
		listdecrypt(pw, fdat.from, fdat.to, 32);
		free(fdat.from);
	} else {	// process in chunks so will handle huge files
		readwriteloop(infile, outfile, pw, 32, 32);
	}

	if (!list) free(outfile);
	free(pw);
	free(infile);
	return 0;
}//main()

void dohelp(int forced)
{
  fputs(helpmsg, stderr);
  exit(forced);
}

void listdecrypt(const char *pw, char *from, char *to, size_t ivsize)
{
	unsigned char result[32];
	char *cp;
	char *pwbuf;
	// pwbuf may be any length subject only to available memory.
	size_t pwblen = strlen(pw) + ivsize;
	size_t pwbuflen = (pwblen < 64) ? 64 : pwblen;
	pwbuf = malloc(pwbuflen + 1);	// terminating '\0'
	memcpy(pwbuf, from, ivsize); // no strcpy(), may have embedded '\0'.
	strcpy(pwbuf + ivsize, pw);
	from += ivsize;
	cp = from;
	// NB arg1 is the input, arg3 64 bit sha256sum, arg4 32 bit sum.
	(void)calcsha256sum(pwbuf, pwblen, pwbuf, result);

	while(1) {
		if (debug) {
			// write the hex version of the sum to stderr
			fprintf(stderr, "%s\n", pwbuf);
		} // debug

		// the actual decryption.
		size_t i;
		for (i=0; i<32; i++) {
			*cp ^= result[i];
			cp++;
			if (cp > to) goto writeresult;	// the only exit point
		}
		// get the next sum
		/*         input64bytes, size, output64bytes, output32bytes */
		(void)calcsha256sum(pwbuf, 64, pwbuf, result);
	}

writeresult:
	processlist(from, to); // Only needs the decrypted image.
} // listdecrypt()

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

void readwriteloop(const char *infile, const char *outfile,
					const char *pw, size_t chunksize, size_t ivsize)
{
	size_t ifsize;
	struct stat sb;
	if (stat(infile, &sb) == -1) {
		perror(infile);
		exit(EXIT_FAILURE);
	}
	ifsize = (size_t) sb.st_size - 1;
	ifsize = (decrypt) ? ifsize - ivsize : ifsize;
	// Open the input file

	FILE *fpi = fopen(infile, "r");
	if(!fpi) {
		perror(infile);
		exit(EXIT_FAILURE);
	}
	FILE *fpo = fopen(outfile, "w");
	if(!fpo) {
		perror(outfile);
		exit(EXIT_FAILURE);
	}

	size_t buflen = chunksize;
	buflen = (ivsize > chunksize) ? ivsize : chunksize;
	char *buf = malloc(buflen);
	size_t pwlen = ivsize + strlen(pw);
	size_t pwbuflen;
	char *pwbuf;	// holds hex format sha256sum also.
	pwbuflen = (pwlen < 64) ? 64 : pwlen;
	pwbuf = malloc(pwbuflen + 1);

	if (decrypt) {
		size_t x = fread(pwbuf, 1, ivsize, fpi);
		x++;	// stop gcc bitching
		//logthisbin(pwbuf, ivsize, "deciv.dat");
	} else {
		char *np = calc_nonce();
		fwrite(np, 1, ivsize, fpo);	// write the iv out unencrypted.
		memcpy(pwbuf, np, ivsize);	// memcpy, np may have embedded '\0'
		//logthisbin(pwbuf, ivsize, "enciv.dat");
	}

	strcpy(pwbuf+ivsize, pw);	// initial key.
	/*
	if (decrypt){
		logthisbin(pwbuf, pwlen, "decivpw.dat");
	} else {
		logthisbin(pwbuf, pwlen, "encivpw.dat");
	}
	*/

	unsigned char brp[32];
	void *binresult = brp;
	size_t totalout = 0;
	(void)calcsha256sum(pwbuf, pwlen, pwbuf, binresult);
	while(1) {
		if(debug) fprintf(stderr, "%s\n", pwbuf);
		size_t bytesread = fread(buf, 1, chunksize, fpi);
		size_t i = 0;
		for(; i < chunksize; i++){
			buf[i] ^= brp[i];
		}
		fwrite(buf, 1, bytesread, fpo);
		totalout += bytesread;
		/* It does not matter when bytesread < chunksize, we just
		 * encrypt a few bytes of garbage in buf beyond the file end,
		 * but only the number of bytes read in get written. */
		if (totalout > ifsize) break;
		(void)calcsha256sum(pwbuf, 64, pwbuf, binresult);
	}

} // readwriteloop()

/* Un-comment to use this.
void logthisbin(void *buf, size_t size, const char *fn)
{
	FILE *fpo = fopen(fn, "w");
	fwrite(buf, 1, size, fpo);
	fclose(fpo);
} // logthisbin()
*/

void shredfile(const char *fn)
{
	/* overwrite the named patterns and then unlink it. */
	FILE * fps = fopen(fn, "r+"); // keep the same inode???
	if (!fps) {
		perror(fn);
		exit(EXIT_FAILURE);
	}
	struct stat sb;
	(void)stat(fn, &sb);
	size_t numbytes = (size_t)sb.st_size;
	unsigned char patterns[3] = {85,/*01010101*/ 170,/*10101010*/ 0 };
	size_t i, j;
	for (i = 0; i < 3; i++) {
		for(j = 0; j < numbytes; j++){
			fwrite(&patterns[i], 1, 1, fps);
		}
		fclose(fps);
		sleep(4);	// enough time for the result to be written out???
		fps = fopen(fn, "r+");
	}
	// now disguise the fact that we have shredded anything.
	FILE *fp = fopen("/dev/random", "r");
	unsigned seed;
	size_t nothing;
	nothing = fread(&seed, 1, sizeof(unsigned), fp);
	nothing++;	// stop gcc bitching.
	srandom(seed);
	fclose(fp);
	numbytes /= sizeof(long int);
	/* Due to truncation on division, this will have the effect of
	 * leaving 0..7 bytes with 0 at the end of the file space. I
	 * don't see that as a problem. I DO NOT want to increase the size
	 * of the file because of the risk of it being written to another
	 * inode if I do.
	 * */
	for(j = 0; j < numbytes; j++){
		long int rdata = random();
		fwrite(&rdata, 1, sizeof(long int), fps);
	}
	fclose(fps);
	sleep(4);
	unlink(fn);
} // shredfile()
