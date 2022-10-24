#include <stdio.h>
#include <stdlib.h>
void Application_Bufferoverflow(char* in_buf){
 for(char c = *in_buf++; c != '\x00'; c = *in_buf++) {
 if(c=='\0') {
 printf("You have been blocked!\n");
 printf("Empty string the sequence\n");
 exit(-1);
 }
 }
}
void CAFtest() {
 char buf[256] = {0};
 printf("\n Application Bufferoverflow Test — input payload here:\n");
 gets(buf);
 Application_Bufferoverflow(buf);
 printf(buf);
}
int main(int argc, char* argv[]) {
 while(1) {
 CAFtest();
 }
}