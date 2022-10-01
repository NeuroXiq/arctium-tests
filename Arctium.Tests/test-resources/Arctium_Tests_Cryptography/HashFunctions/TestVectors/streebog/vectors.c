// This file was used to generate test vectors
// and after generation first line is empty (manually removed first line after running this program)
// Streebog was compiled from "https://github.com/adegtyarev/streebog" repository
// and compiled run with parameters below to generate sample test vectors

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	int bufsize = 1024 * 1024;
	char* c = malloc(1026);
	char* tocall = malloc(bufsize);

	for (int i = 0; i < 1025; i++)
	{
		memset(c, 0, 1026);
		for (int j = 0; j < i; j++)
		{
			char k = (j % 25) + 65;
			c[j] = (char)k;
		}

		printf("%s=", c);
		fflush(stdout);
		sprintf(tocall, "~/my-files/projects/streebog/gost3411-2012 -2 -q -s %s", c);
		system(tocall);
		// printf("%s\n",tocall); 
	}

	//system("~/my-files/projects/streebog/gost3411-2012 -5 -s %s");
	return 0;
}
