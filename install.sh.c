char *functions;
char *includes;
char *main_body;
char iv[17]="\0";
char key[33]="\0";
char prod_serial[256]="/sys/devices/virtual/dmi/id/product_serial";
char prod_uuid[256]="/sys/devices/virtual/dmi/id/product_uuid";
#include <fcntl.h>
#include <openssl/buffer.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
int ctx_len=3760;
unsigned char *crypted_script="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\n"
"96gXOWsBOukgOAq4jiUcAQ==\n"
;
unsigned char uuid[37]="\0";
unsigned char serial[17]="\0";
int getuuid(char *uuid)
{ FILE *filepointer;
  int i=0,rb=0;
  char *s, *end;
  if((filepointer=fopen(prod_uuid,"r"))==NULL)
  {
#ifdef __linux__
    if((filepointer=popen("dmidecode -s system-uuid","r"))==NULL)
    { return(-1); /*failed running dmidecode*/
    }
#elif __APPLE__
    if((filepointer=popen("system_profiler SPHardwareDataType | awk '/UUID/ { print $3; }'","r"))==NULL)
    { return(-1); /*failed running system_profiler */
    }
#elif __FreeBSD__
    if((filepointer=popen("gpart list | awk -v i=0 '/rawuuid:/ {if (i<1) print $NF; i++}'","r"))==NULL)
    { return(-1); /*failed running gpar or awk */
    }
#elif __OpenBSD__
    if((filepointer=popen("disklabel $(df / |awk -F'[/ ]' 'END{print $3}') | awk '/duid:/ {print $NF}' |md5 |awk '{printf(\"%sopen\",$1)}'","r"))==NULL)
    { return(-1); /*failed running disklabel, md5 or awk */
    }
#else
    printf("Unsupported platform\n");
    return(-1);
#endif
    if((rb=fread(uuid,1,36,filepointer))!=36)
    { return(-2); /*could not read enough data from "dmidecode -s system-uuid"*/
    } else pclose(filepointer);
  } else
  {
    if((rb=fread(uuid,1,36,filepointer))!=36)
    { return(-3); /*could not read enough data from prod_uuid*/
    } else fclose(filepointer);
  }
  return strlen(uuid); 
}
int makekey (char *key , char *uuid)
{ int i=0;
  char *s, *end; 
  s=(char*)uuid;
  while (*s)
  { if ( *s != '-') key[i++]=*s;
    s++;
  }
  return strlen(key);
}
int getserial(char *serial)
{ FILE *filepointer;
  int rb=0;
  char *s, *end;
  char buff[17]="\0";
  /* attempt to open sys produtc serial */
  if((filepointer=fopen(prod_serial,"r"))==NULL)
  { //printf("File open error. Will attempt to use dmidecode.\n");
#ifdef __linux__
    if((filepointer=popen("dmidecode -s system-serial-number","r"))==NULL)
    { return(-1); /* failed running dmidecode */
    }
#elif __APPLE__
    if((filepointer=popen("system_profiler SPHardwareDataType | awk '/Serial Number/ { print $4 }'","r"))==NULL)
    { return(-1); /* failed running system_profiler */
    }
#elif __FreeBSD__
    if((filepointer=popen("gpart list | awk -v i=0 '/rawuuid:/ {if (i==2) {print $NF;} i++}'","r"))==NULL)
    { return(-1); /*failed running gpart or awk */
    }
#elif __OpenBSD__
    if((filepointer=popen("disklabel $(df / |awk -F'[/ ]' 'END{print $3}') | awk '/duid:/ {print $NF}'","r"))==NULL)
    { return(-1); /*failed running disklabel or awk */
    }
#else
    printf("Unsupported platform\n");
    return(-1);
#endif    
    rb=fread(buff,1,16,filepointer);
    pclose(filepointer);
  } else
  {
    rb=fread(buff,1,16,filepointer);
    fclose(filepointer);
  }
  if(rb<1)
  { /*if you get in in here nothing was read so migh as well just give up */
    printf("Insufficient data to identify.\n");
    exit(1);
  }
  if(rb!=16) strncpy(serial,buff,rb-1);
  else strcpy(serial,buff);
  serial[rb]=0;
  return strlen(serial);
}
int makeiv (char *iv, char *serial)
{ FILE *filepointer;
  int rb=0;
  char *s, *end;
  rb=strlen(serial);
  if(rb!=16)
  { strncat(iv,serial,rb-1);
    if(rb<9)  strncat(iv,prod_serial,17-rb);
    strncat(iv,serial,17-rb);
  } else strcpy(iv,serial);
  return strlen(iv);
}
int obencrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{ EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) exit(1);
  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    exit(1);
  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary*/
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    exit(1);
  ciphertext_len = len;
  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.*/
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) exit(1);
  ciphertext_len += len;
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{ EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) exit(1);
  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    exit(1);
  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary*/
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    exit(1);
  plaintext_len = len;
  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.*/
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) exit(1);
  plaintext_len += len;
  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}
char *unbase64(unsigned char *input, int length)
{ BIO *b64, *bmem;
  char *buffer = (char *)malloc(length);
  memset(buffer, 0, length);
  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new_mem_buf(input, length);
  bmem = BIO_push(b64, bmem);
  BIO_read(bmem, buffer, length);
  BIO_free_all(bmem);
  return buffer;
}
char *base64(const unsigned char *input, int length)
{ BIO *bmem, *b64;
  BUF_MEM *bptr;
  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
  char *buff = (char *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);
  buff[bptr->length-1] = 0;
  BIO_free_all(b64);
  return buff;
}
int mk_sh_c ( char *infilename, char *key, char *iv , bool reusable, char *serial, char *uuid)
{ unsigned char *plaintext, *ciphertext, *b64ctx;
  char *outfilename;
  FILE *infile,*outfile;
  int rb,insize,ctsize,i; 
  char str[256]="\0";
  outfilename=malloc(strlen(infilename)+2);
  strcpy(outfilename,infilename);
  strcat(outfilename,".c");
  if((outfile=fopen(outfilename,"wb"))==NULL)
  return(-1); /*failed opening intermediate c source file*/
  if((infile=fopen(infilename,"r"))==NULL)
  return(-2); /*failed opening infile*/
  fseek(infile,0L,SEEK_END);
  insize=ftell(infile);
  rewind(infile);
  plaintext=malloc(insize);
  ciphertext=malloc(2*insize);
  b64ctx=malloc(2*insize);
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_no_config();
  if((rb=fread(plaintext,1,insize,infile))!=insize)
  return(-3); /*did not read the entire infile */ 
  ctsize=obencrypt (plaintext,insize,key,iv,ciphertext); 
  b64ctx=base64(ciphertext,ctsize);
  printf("input filename: %s\n",infilename);
  printf("input file size: %i\n",insize);
  printf("ciphertext size: %i\n",ctsize);
  printf("base64 encoded ciphertext: %zu : %zu whole lines\n",strlen(b64ctx),strlen(b64ctx)/65);
  printf("intermediate c generated filename: %s\n",outfilename);
  fwrite(includes,1,strlen(includes),outfile);
  sprintf(str,"int ctx_len=%i;\n",ctsize);
  fwrite(str,1,strlen(str),outfile);
  fwrite("unsigned char *crypted_script=",1,30,outfile);
  for (i=0;i<strlen(b64ctx)/65;i++)
  { fputc(34,outfile); 
    fwrite(b64ctx+(65*i),1,64,outfile); 
    fputc(92,outfile);
    fputc('n',outfile);
    fputc(34,outfile); 
    fputc(10,outfile); 
  }
  if((i*65)< strlen(b64ctx))
  { fputc(34,outfile);
    fwrite(b64ctx+(65*i),1,strlen(b64ctx)-(65*i),outfile);
    fputc(92,outfile);
    fputc('n',outfile); 
    fputc(34,outfile);
    fputc(10,outfile);
  }
  fwrite(";\n",1,2,outfile);
if(reusable)
{ printf("Creating reusable intermadiate c file\n");
  fwrite("unsigned char uuid[37]=",1,23,outfile);
  fputc(34,outfile);
  fwrite(uuid,1,strlen(uuid),outfile);
  fputc(34,outfile);
  fwrite(";\n",1,2,outfile);
  fwrite("unsigned char serial[17]=",1,25,outfile);
  fputc(34,outfile);
  fwrite(serial,1,strlen(serial),outfile);
  fputc(34,outfile);
  fwrite(";\n",1,2,outfile);
} else
{ printf("Creating non reusable binary\n"); 
  fwrite("unsigned char uuid[37]=",1,23,outfile);
  fputc(34,outfile);
  fputc(92,outfile); 
  fputc('0',outfile); 
  fputc(34,outfile);
  fwrite(";\n",1,2,outfile);
  fwrite("unsigned char serial[17]=",1,25,outfile);
  fputc(34,outfile);
  fputc(92,outfile);
  fputc('0',outfile);
  fputc(34,outfile);
  fwrite(";\n",1,2,outfile);
}
  fwrite(functions,1,strlen(functions),outfile);
  fwrite("\n",1,1,outfile);
  fwrite(main_body,1,strlen(main_body),outfile);
  fclose(outfile);
  fclose(infile);
  free(outfilename);
  free(plaintext);
  free(ciphertext);
  free(b64ctx);
  EVP_cleanup();
  ERR_free_strings();
  return(0);
}

int main(int argc, char *argv[])
{ char str[256]="\0";
  int rb,pid,status,len;
  char *ctx, *plaintext;
  int pipefd;
  char pipename[256]="\0";
  int i,j;
  static const char *copyright="Obfuscated Bash\n"
  "Copyright (C) 2017- Davide Rao: louigi600 (at) yahoo (dot) it\n"
  "\nThis program is free software; you can redistribute it and/or modify\n"
  "it under the terms of the GNU General Public License as published by\n"
  "the Free Software Foundation; either version 2 of the License, or\n"
  "(at your option) any later version provided that no poit of the\n"
  "AA License is violated.\n";
  if(strlen(uuid)==0) getuuid(uuid);  
  makekey(key,uuid);
  if(strlen(serial)==0) getserial(serial);
  makeiv(iv,serial);
  ctx=malloc(strlen(crypted_script));
  plaintext=malloc(strlen(crypted_script));
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_no_config();
  ctx=unbase64(crypted_script,strlen(crypted_script));
  rb=decrypt(ctx,ctx_len,key,iv,plaintext);
  sprintf(pipename,"/tmp/%i",getpid());
  if(mkfifo(pipename, 0666)!=0)
  { unlink(pipename); /* assuming it failed because a file by that name exists */
    if(mkfifo(pipename, 0666)!=0)
    { printf("Aborting: could not create named pipe %s\n",pipename);
      exit(1);
    }
  }
  switch (pid=fork()) 
  { case -1: /* Handle fork error */
      printf("Error forking interpreter.\n");
      break;
    case 0:  /* Child - reads from named pipe */
       printf("\0");
       enum { MAX_ARGS = 64 };
       char *args[MAX_ARGS];
       char arg2[15]="\0";
       char **argp=args;
       args[0]="bash";
       args[1]="-c";
       sprintf(arg2,"source %s",pipename);
       argp[2]=arg2;
       argp[3]=argv[0];
       if (argc==1) args[4]=NULL;
       else
       { for(i=1;i<argc;i++)
         {  argp[i+3]=argv[i];
         }
         args[i+3]=NULL; 
       }
       fflush(stdout);
       execvp("bash",args);
       printf("Interpreter crashed.\n");
       break;
    default: /* Parent - writes to named pipe */
       pipefd=open(pipename, O_WRONLY);  
       write(pipefd,plaintext,rb);
       close(pipefd);
       break;
  }
  unlink(pipename);
  EVP_cleanup();
  ERR_free_strings(); 
  free(ctx);
  free(plaintext);
  waitpid(pid,&status,0);
  return(0);
}
