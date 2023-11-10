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
int ctx_len=1408;
unsigned char *crypted_script="wuFamvhiYyPbK2v7Y6armuaBbU9mD9JHw78BrWJahJ26f3+QnZKZq+UBkrC4IsfP\n"
"V57/kxpd5xVqLVWv3zCmDNaeHkBkL6EFFoebBZGaeFoV7keHjNRMtXtMHLsMH2T3\n"
"prm+EtJtehsTemZCOO4u0jU86WMmI9ww7M3QVWpVxJJd2OLf82N40Z1xSE/GRbB5\n"
"YX9BMr6swyO50UO8bxLRG6fA769OpdDl1mq9hkXKDaaHVptT+a/XhOvsHj+YWkiU\n"
"UrsiF69pPMVfNjZfF+yyotdE4ih3OlnzwEuZdHgRMZP3zdHFM6SWIgB1CYfw2f5B\n"
"XuhVSADwXMAeqMlDZGHA8zW8Bu1RVfFLOSMe93vPg/M6AMQ3VvhSZuSbsHjb7e/X\n"
"2gH5l8rIF+ehIU8BVxFQt9lszv2mHAYIkYo0CgOOkS4+kLJmlW9kIOYaHtULBlH8\n"
"VXgInA93KqO5AcypBSLJnfZieO1R1v5YOMOEJG3ai5VfNBPPks8W7iFWma4R4rIs\n"
"PxXpXt/p44iQpXBrD0sst49NQIWbcqQfEa7KqAoKiNm+go05MlkJ2RhpcdBRdJyu\n"
"gTp08fGWqZEs0Tbk7zT1iWQLJHu32Xq1cE5UVFuxRHqnavqbQl84TtPsF4kfsyRe\n"
"HuHDJotUObk8LHL8HWWx5N1kVr2B6ABxRKH6bQDjue+t+0xlPI37sqfMjFEdSYWN\n"
"b1pnfwDFW5Vp/taGhPkNEMfOspMpRmU/YkGbsPP3JxXWxUIU3nf0bsIRD2DJlYvs\n"
"sopbE/o/6LlZusMmrX9oUtymmSSstehYKciMhi3T0fPEqg/7sclgRZ+4KqPILacj\n"
"JMXwAj/oZy3drLbPj3E0K4x4Qr5GeTqTGV/XmC3MP3dplHrCNt6S9QXlBCri27Sg\n"
"SLPPTqCLsVva6fajHNzYBoURDkUzzfgvmA6U+i85nDCvK8yor7ML4q2HMudkpY9V\n"
"oT2px7oJ98P3GEvZxj4Z/lMjjNmW3yCdjQet1Q2lDaxj3aafIzDEnQsOj/rOqwKU\n"
"ZL8GlPDiNLyfmcS9pooDWpnQxYazI3YBBssxS49CRQPyW7mDrBd2QcNckwFpQB26\n"
"mhuyWa8g9H5v65JvFV8mjoYXTWuYHmG0ZMrmydAqfRvNcd3RTwojV25iXl2/EJ3n\n"
"EmzrbcLXGpnZzzGHZIuo/MW1BZcdkn+64MM/KigdCNOpDn5ns3LpW1uC+LP/q/QG\n"
"T3qsUoKfnzFTMsLGiV1gEhuVQL8EY4HQS13117TEzYm6bM0NerP81FFWpobluF15\n"
"aqYUcjh2H92+Qiix/ojgvD1G0TXeX5qsx67VxNP/GJnZBklbHiXwbaJmN+YZBSyJ\n"
"GmBR5ZaOXT+nG3hQRSwa1/q1WiHGIwCvu1tgbEdmc8nMBCVLG/ZOdfXvJZ6BAnFm\n"
"tC+19PX9Avctvq/ZHci+zMf866ilcftkw3QvFYlPdxyKaXm0+SE/dNiftJ7oiOjN\n"
"7yoIZoipSUwsfyfVTngij5hCztEscwbvFn3IPaZFa0/CveDEHbsNBZ6BmhCHQjpn\n"
"X+ch69Nnd3Sz/x2GyIfQ8LLGDs+CJNujZDWbtKBGuoC+jhU9DFVDCcqEExa0YTTD\n"
"4gCBQRmaqcRI3H5xobBupG1uKW2KhbWlmWKwDBOP1jVK8cbdjNuq/yjTvCCF0GqO\n"
"SVJGUrI7gCa9u9QF+xBem3oPWKdD0StVvDJ1mAvLFTAn+P06SQ9LfO3ZDBunf8X/\n"
"9gMRjK0rFrow10yym2LER4PvadA/LBAv25DrSxdMYwAjprgFin9FbRVh+9+s4CKq\n"
"Lt7GmJVldZ0IFbo0hJj54mqTp2MWNWJAGmPm9RVJCRqwqOppbB/YRxjXS+Sd4Zl0\n"
"vmTL6POky47fuNJYg6q+rg==\n"
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
