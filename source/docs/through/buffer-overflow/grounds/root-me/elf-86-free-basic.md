# ELF x86: Use after free basic

[root-me challenge](https://www.root-me.org/en/Challenges/App-System/ELF-x86-Use-After-Free-basic):

Environment configuration:

```text
PIE 	Position Independent Executable 	 No 
RelRO 	Read Only relocations 	 Yes 
NX 	Non-Executable Stack 	 Yes 
Heap exec 	Non-Executable Heap 	 Yes 
ASLR 	Address Space Layout Randomization 	 Yes 
SRC 	Source code access 	 Yes 
```

Source code:

```text
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
 
#define BUFLEN 64
 
struct Dog {
    char name[12];
    void (*bark)();
    void (*bringBackTheFlag)();
    void (*death)(struct Dog*);
};
 
struct DogHouse{
    char address[16];
    char name[8];
};
 
int eraseNl(char* line){
    for(;*line != '\n'; line++);
    *line = 0;
    return 0;
}
 
void bark(){
    int i;
    for(i = 3; i > 0; i--){
        puts("UAF!!!");
        sleep(1);
    }
}
 
void bringBackTheFlag(){
    char flag[32];
    FILE* flagFile = fopen(".passwd","r");
    if(flagFile == NULL)
    {
        puts("fopen error");
        exit(1);
    }
    fread(flag, 1, 32, flagFile);
    flag[20] = 0;
    fclose(flagFile);
    puts(flag);
}
 
void death(struct Dog* dog){
    printf("%s run under a car... %s 0-1 car\n", dog->name, dog->name);
    free(dog);
}
 
struct Dog* newDog(char* name){
    printf("You buy a new dog. %s is a good name for him\n", name);
    struct Dog* dog = malloc(sizeof(struct Dog));
    strncpy(dog->name, name, 12);
    dog->bark = bark;
    dog->bringBackTheFlag = bringBackTheFlag;
    dog->death = death;
    return dog;
}
 
void attachDog(struct DogHouse* dogHouse, struct Dog* dog){
    printf("%s lives in %s.\n", dog->name, dogHouse->address);
}
 
void destruct(struct DogHouse* dogHouse){
    if(dogHouse){
        puts("You break the dog house.");
        free(dogHouse);
    }
    else
        puts("You do not have a dog house.");
}
 
struct DogHouse* newDogHouse(){
    char line[BUFLEN] = {0};
   
    struct DogHouse* dogHouse = malloc(sizeof(struct DogHouse));
   
    puts("Where do you build it?");
    fgets(line, BUFLEN, stdin);
    eraseNl(line);
    strncpy(dogHouse->address, line, 16);
   
    puts("How do you name it?");
    fgets(line, 64, stdin);
    eraseNl(line);
    strncpy(dogHouse->name, line, 8);
   
    puts("You build a new dog house.");
   
    return dogHouse;
}
 
int main(){
    int end = 0;
    char order = -1;
    char nl = -1;
    char line[BUFLEN] = {0};
    struct Dog* dog = NULL;
    struct DogHouse* dogHouse = NULL;
    while(!end){
        puts("1: Buy a dog\n2: Make him bark\n3: Bring me the flag\n4: Watch his death\n5: Build dog house\n6: Give dog house to your dog\n7: Break dog house\n0: Quit");
        order = getc(stdin);
        nl = getc(stdin);
        if(nl != '\n'){
            exit(0);
        }
        fseek(stdin,0,SEEK_END);
        switch(order){
        case '1':
            puts("How do you name him?");
            fgets(line, BUFLEN, stdin);
            eraseNl(line);
            dog = newDog(line);
            break;
        case '2':
            if(!dog){
                puts("You do not have a dog.");
                break;
            }
            dog->bark();
            break;
        case '3':
            if(!dog){
                puts("You do not have a dog.");
                break;
            }
            printf("Bring me the flag %s!!!\n", dog->name);
            sleep(2);
            printf("%s prefers to bark...\n", dog->name);
            dog->bark();
            break;
        case '4':
            if(!dog){
                puts("You do not have a dog.");
                break;
            }
            dog->death(dog);
            break;
        case '5':
            dogHouse = newDogHouse();
            break;
        case '6':
            if(!dog){
                puts("You do not have a dog.");
                break;
            }
            if(!dogHouse){
                puts("You do not have a dog house.");
                break;
            }
            attachDog(dogHouse, dog);
            break;
        case '7':
            if(!dogHouse){
                puts("You do not have a dog house.");
                break;
            }
            destruct(dogHouse);
            break;
        case '0':
        default:
            end = 1;
        }
    }
    return 0;
}
```

## Resources

* [Blackhat EU-16 - Use-After-Use-After-Free - Exploit UAF by generating your own - Guanxing Wen](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/EN%20-%20Blackhat%20EU-16%20-%20Use-After-Use-After-Free%20-%20Exploit%20UAF%20by%20generating%20your%20own%20-%20Guanxing%20Wen.pdf)
* [From collision to exploitation: Unleashing Use-After-Free vulnerabilities in Linux Kernel](https://repository.root-me.org/Exploitation%20-%20Syst%C3%A8me/Unix/EN%20-%20From%20collision%20to%20exploitation:%20Unleashing%20Use-After-Free%20vulnerabilities%20in%20Linux%20Kernel.pdf)