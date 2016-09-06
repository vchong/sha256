#include <stdlib.h>
#include <stdio.h>

void SHA();

void testdef(void)
{
	SHA();
}

#define HASH SHA

//so this becomes implementation of void SHA(void)
void HASH(void)
{
	printf("HASH\n");
}

//this is like a wrapper f SHA()
//but do additional stuffs
//before actually calling SHA()
static void sha(void)
{
	printf("sha before SHA\n");
	SHA(); //call original SHA()
	printf("sha after SHA\n");
}

# ifdef SHA
#  undef SHA
# endif
# define SHA sha //all SHA() above this will call HASH() while all below will call sha()

void testdef2(void)
{
	SHA(); //so this becomes sha()
}

int main (int argc, char **argv)
{
	printf("sizeof(unsigned int) = %lu\n", sizeof(unsigned int));
	printf("sizeof(int) = %lu\n", sizeof(int));

	printf("%d %d\n", 1 + (1 < 0) /* false */, 1 + (0 < 1) /* true */);

	//printf("%d = %d\n", 100/64, 100>>6);
	//printf("%d = %d\n", 100*64, 100<<6);

	//testdef();
	//testdef2();
	return 0;
}
