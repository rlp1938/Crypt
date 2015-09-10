
/*      dicewords.c
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

/*
 * The method used;
 * 1. I seed the random number generator with the first available
 * bytes in /dev/random, interpreted as an unsigned int.
 * 2. I then generate the required number of words, 3 or greater using
 * the random() function. These words are read from the diceware word
 * list.
 * Maybe not as crypto secure as rolling real dice, but I think that it
 * will be close.
*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <ctype.h>
#include "readfile.h"

char *helpmsg = "\n\tUsage: dicewords -h \n"
  "\n\tUsage: dicewords no_of_words (3 minimum) \n"
  "\n\tOptions:\n"
  "\t-h outputs this help message.\n"
  ;

void dohelp(int forced);
char *wordfromindex(char *from, char *to, char *index);

int main(int argc, char **argv)
{
	int opt;
	int words;

	if(argc < 2) dohelp(1);

	while((opt = getopt(argc, argv, ":h")) != -1) {
		switch(opt){
		case 'h':
			dohelp(0);
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
		fprintf(stderr, "No number of words [3-7] provided\n");
		dohelp(1);
	}

	// 2. Check that it's a number [3 or greater]
	words = strtol(argv[optind], NULL, 10);
	if (words < 3) dohelp(1);

	// read our word list
	struct fdata fdat = readfile(
			"/usr/local/share/dicewords/diceware.wordlist.asc", 0, 1);
	char *begin = fdat.from;
	char *end = fdat.to;
	char *tmp;
	// convert file data to array of strings.
	tmp = begin;
	while(tmp < end) {
		if (*tmp == '\n') *tmp = '\0';
		tmp++;
	}


	// count how many lines maybe in the file
	/*
	int j;
	int count = 0;
	for (j=11111; j<=66666; j++) {
		char buf[6];
		int x;
		int countable = 1;
		sprintf(buf, "%d", j);
		for(x=0; x<5; x++) {
			if (buf[x] == '0'|| buf[x] > '6') countable = 0;
		} // for(x..
		if(countable) count++;
	}
	fprintf(stdout, "expected lines: %i\n", count);
	*/
	// the random stuff
	//printf("sizeof unsigned %lu\n", sizeof(unsigned));
	FILE *fp = fopen("/dev/random", "r");
	unsigned seed;
	size_t nothing = fread(&seed, 1, sizeof(unsigned), fp);
	nothing++; // stop gcc bitching.
	srandom(seed);
	fclose(fp);

	int wc;
	for (wc=0; wc<words; wc++) {
		char windex[6];
		windex[0] = '\0';
		int i;
		for (i=0; i<5; i++) {
			char bf[2];
			int rnum = random()%6 + 1;
			sprintf(bf, "%d", rnum);
			strcat(windex, bf);
		} // for(i..)
		fprintf(stdout, "%s ", wordfromindex(begin, end, windex));
	} // for(wc..)
	fputs("\n", stdout);
	return 0;
}//main()

void dohelp(int forced)
{
  fputs(helpmsg, stderr);
  exit(forced);
}

char *wordfromindex(char *from, char *to, char *index)
{
	static char *cp;

	/* The search for a well formed set of 5 dice rolls cannot fail.
	 * I have tested all combinations of 11111 - 66666, consisting only
	 * of digits 1 .. 6. This amounts to 7776 combinations, the same as
	 * the number of lines in the data file.
	*/
	cp = from;
	cp = memmem(from, to - from, index, 5); // always 5 long.
	cp += 5;	// get past the index.
	while(isspace(*cp)) cp++;	// get past the spaces before the word.
	return cp;
} //
