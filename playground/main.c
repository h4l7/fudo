#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main (int argc, char *argv[], char *envp[]) {
    printf("argc = %d\n", argc);
  
    for (int i = 0; i < argc; i++) {
      printf("argv[%d] = %s\n", i, argv[i]);
    }
  
    printf("\n");
    
    while (*envp) {
	size_t len = strlen(*envp);
	printf("len=%d\tptr=%p\t*ptr=%p %s\n", len, envp, *envp, *envp);
	envp++;
    }

    
    return EXIT_SUCCESS;
}

