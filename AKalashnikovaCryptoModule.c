#include <ctype.h>
#include "AKalashnikovaChaCha20Core.c"

#define PLAIN_FILE_NAME "plain.txt"
typedef unsigned char BYTE;

size_t fillBufferWithPlainText(uint8_t **buffer);
uint8_t initializeUsersPrngKey(uint8_t inputKey[65]);
int8_t convertAscii2Dec(char ch);
void prettyprintBstr(char *S, BYTE *A, int L);

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  ((byte) & 0x80 ? '1' : '0'), \
  ((byte) & 0x40 ? '1' : '0'), \
  ((byte) & 0x20 ? '1' : '0'), \
  ((byte) & 0x10 ? '1' : '0'), \
  ((byte) & 0x08 ? '1' : '0'), \
  ((byte) & 0x04 ? '1' : '0'), \
  ((byte) & 0x02 ? '1' : '0'), \
  ((byte) & 0x01 ? '1' : '0')
        

int32_t main (void)
{
    // Run selftest
    if (chacha20_run_selftests(&cc20ctx) > 0)
    {
        printf("Selftest with RFC 7539 test vectors: FAIL. Exit.\n");
        exit(EXIT_FAILURE);
    }
    printf("Selftest with RFC 7539 test vectors: PASSED.\n");

    // Initialize the context
    chacha20_init_context(&cc20ctx, key, nonce, 1);

    // Prepare plain text
	uint8_t *buffer = NULL;
    size_t bufferSize = fillBufferWithPlainText(&buffer);
    if(bufferSize < 1)
    {
        printf("Exit due to previous error.\n");
        exit(EXIT_FAILURE);
    }    
    printf (":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	printf ("Initial buffer:\n");
	printf ("%s\n", buffer);
    printf (":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");

    // Ask seed from user
    // Default seed is "0f6b75ab2bc471c70c9dbd5d80e68ba310F5B618BDB6F2262FCC597BB230B3EF"
    printf("Enter 64 bytes of seed value or just press ENTER key now to use default seed value:\n");
	uint8_t inputKey[65] = {};
    char *result = fgets((char*)inputKey, 65, stdin);
    if(result != NULL && *result != '\n')
    {
        if(initializeUsersPrngKey(inputKey))
        {
            printf("Exit due to previous error.\n");
            exit(EXIT_FAILURE);
        }
    }

    // Initialize ChaCha20 context
    chacha20_init_context(&cc20ctx, key, nonce, 1);

    // Encrypt the buffer
	chacha20_xor(&cc20ctx, buffer, bufferSize);
    printf (":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	printf ("Encrypted buffer:\n");
	printf ("%s\n", buffer);

    printf (":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");
    char title[] = "Hex representation of encrypted buffer:\n";
    prettyprintBstr(title, buffer, bufferSize);
    printf (":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");

    printf ("Binary representation of encrypted buffer:\n");
    for (size_t i = 0; i < bufferSize; i++)
    {
        printf(" "BYTE_TO_BINARY_PATTERN" ", BYTE_TO_BINARY(buffer[i]));
	    if ((i + 1)%8 == 0) printf ("\n");
    }
    printf ("\n");
    printf (":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");

    // Initialize ChaCha20 context
    chacha20_init_context(&cc20ctx, key, nonce, 1);

    // Decrypt the buffer
	chacha20_xor(&cc20ctx, buffer, bufferSize);
	printf ("Decrypted buffer:\n");
	printf ("%s\n", buffer);
    printf (":::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n");

    exit(EXIT_SUCCESS);
}

size_t fillBufferWithPlainText(uint8_t **buffer)
{
    char *memory = NULL;
	size_t fileSize = -1;
    size_t readSize = -1;

	FILE *plainText = fopen(PLAIN_FILE_NAME, "r");
	if (!plainText)
	{
		printf("Error: Can't open the file '"PLAIN_FILE_NAME"'.");
		return -1;
    }
	
	fseek(plainText, 0L, SEEK_END);
	fileSize = ftell(plainText);
	if (fileSize < 1)
	{
		printf("Error: Can't read the file '"PLAIN_FILE_NAME"'.");
	    fclose(plainText);
		return -2;
    }

	printf("File size is %ld bytes.\n", fileSize);
	memory = (char *) malloc(fileSize);
	if (memory == NULL)
	{
		printf("Error: Can't allocate a memory.");
	    fclose(plainText);
		return -3;
    }

	fseek(plainText, 0L, SEEK_SET);
	readSize = fread(memory, 1, fileSize, plainText);
	if (fileSize != readSize)
	{
		printf("Error: Read %ld bytes of %ld bytes from the file '"PLAIN_FILE_NAME"'.", readSize, fileSize);
        free(memory);
	    fclose(plainText);
		return -4;
    }
    
	printf ("Read %ld bytes to buffer from file.\n", readSize);
	fclose(plainText);
	
    *buffer = (uint8_t *) memory;
    return readSize;
}

int8_t convertAscii2Dec(char ch)
{
    int8_t dec = -1;

    if (isxdigit(ch))
    {
        if (isdigit(ch))
            dec = (ch - '0');
        else
            dec = (tolower(ch) - 'a' + 10);
    }

    return dec;
}

uint8_t initializeUsersPrngKey(uint8_t inputKey[65])
{
    for (size_t i = 0; i < 32; i++)
    {
        int8_t dec1 = convertAscii2Dec(inputKey[2*i]);
        int8_t dec2 = convertAscii2Dec(inputKey[2*i + 1]);
        if(dec1 < 0 || dec2 < 0)
        {
            printf("Error: Wrong seed in %ld position: '%c%c'. Exit.\n", i, inputKey[2*i], inputKey[2*i + 1]);
            return 1; // failure
        }

        //  Converting from Hex to Dec
        key[i] = dec1*16 + dec2;
    }

    return 0; // success
}

void prettyprintBstr(char *S, BYTE *A, int L)
{
	int		i, extra, ctrb, ctrl;

	if ( L == 0 )
		printf("%s <empty>", S);
	else
		printf("%s\n\t", S);
	extra = L % 24;
	if ( extra ) {
		ctrb = 0;
		for ( i=0; i<24-extra; i++ ) {
			printf("  ");
			if ( ++ctrb == 4) {
				printf(" ");
				ctrb = 0;
			}
		}

		for ( i=0; i<extra; i++ ) {
			printf("%02X", A[i]);
			if ( ++ctrb == 4) {
				printf(" ");
				ctrb = 0;
			}
		}
		printf("\n\t");
	}

	ctrb = ctrl = 0;
	for ( i=extra; i<L; i++ ) {
		printf("%02X", A[i]);
		if ( ++ctrb == 4) {
			ctrl++;
			if ( ctrl == 6 ) {
				printf("\n\t");
				ctrl = 0;
			}
			else
				printf(" ");
			ctrb = 0;
		}
	}
	printf("\n\n");
}


