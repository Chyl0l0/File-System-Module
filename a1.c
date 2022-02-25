#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#define MAX_BUFF 4096
#define MAGIC_VALUE 113 // ascii code for q

typedef enum
{
    FALSE,
    TRUE
} bool;

#pragma pack(1)
typedef struct
{
    char name[13];
    unsigned short type;
    unsigned int offset;
    unsigned int size;
} Section_Header;

typedef struct
{
    unsigned char version;
    unsigned char sections_number;
    Section_Header *sections;

} Header;

//list option
int list(const char *path, bool recursive, int perms, int size_greater)
{
    //checking if the path is not secure
    if (strstr(path, ".."))
    {

        printf("ERROR\ninvalid directory path\n");
        return -1;
    }
    char full_path[PATH_MAX];
    DIR *dir = NULL;
    struct stat stat_buffer;
    struct dirent *entry = NULL;

    dir = opendir(path);
    //checking if the directory could be open
    if (dir == NULL)
    {
        printf("ERROR\ninvalid directory path\n");
        return -1;
    }
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            //concatenating the path
            snprintf(full_path, PATH_MAX, "%s/%s", path, entry->d_name);
            if (lstat(full_path, &stat_buffer) == 0)
            {
                //checking if the current file is a directory (only if the recursive flag is set to true)
                if (recursive && S_ISDIR(stat_buffer.st_mode))
                {
                    //if no filter is applied, we print the path
                    if (!perms && !size_greater)
                    {
                        printf("%s\n", full_path);
                    }
                    //permissions filter
                    else if (perms == (0777 & stat_buffer.st_mode))
                    {
                        printf("%s\n", full_path);
                    }
                    list(full_path, recursive, perms, size_greater);
                }
                else
                {
                    //if no filter is applied, we print the path
                    if (!perms && !size_greater)
                    {
                        printf("%s\n", full_path);
                    }
                    //permissions filter
                    else if (perms && (perms == (0777 & stat_buffer.st_mode)))
                    {
                        printf("%s\n", full_path);
                    }
                    //size filter
                    else if (S_ISREG(stat_buffer.st_mode) && size_greater && stat_buffer.st_size > size_greater)
                    {
                        printf("%s\n", full_path);
                    }
                }
            }
        }
    }
    closedir(dir);
    return 0;
}

//function for extracting permisions from a string into an int
int extract_permisions(const char *perm_string)
{

    int perms = 0;
    for (int i = 0; i < 9; i++)
    {
        //checking if the string respects the format
        if (perm_string[i] == '-')
        {
            perms = (perms << 1) | 0;
        }
        else if (i % 3 == 0 && perm_string[i] == 'r')
        {
            perms = (perms << 1) | 1;
        }
        else if (i % 3 == 1 && perm_string[i] == 'w')
        {
            perms = (perms << 1) | 1;
        }
        else if (i % 3 == 2 && perm_string[i] == 'x')
        {
            perms = (perms << 1) | 1;
        }
        else
        {
            return -1;
        }
    }
    return perms;
}
//parse option
int parse(const char *path, bool findall, bool extract, int section, int *offset, int *size)
{
    const short version_low = 88;
    const short version_high = 166;
    const short section_low = 6;
    const short section_high = 19;
    const short section_size = 23;
    const short max_size = 1499;

    //flag array, used for validating the type
    int max_type = 76;
    bool types[76] = {0};
    types[75] = TRUE, types[38] = TRUE, types[72] = TRUE, types[67] = TRUE, types[60] = TRUE;

    Header header;
    char magic = '\0';
    short header_size = 0;
    //opening the file
    int fd = -1;
    fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        if (!findall)
            perror("invalid file\n");
        return -1;
    }
    char buffer[MAX_BUFF];
    //reading the header size and the magic word
    lseek(fd, -3, SEEK_END);
    if (read(fd, &buffer, 3) != 3)
    {

        perror("reading error");
        close(fd);
        return -2;
    }

    memcpy(&header_size, buffer, 2);
    magic = buffer[2];
    //validating the magic word
    if (magic != (char)MAGIC_VALUE)
    {
        if (!findall)
            printf("ERROR\nwrong magic\n");
        close(fd);
        return -3;
    }
    //moving at the begining of the header and reading the version and the section number
    lseek(fd, -header_size, SEEK_END);
    if (read(fd, &buffer, 2) != 2)
    {
        perror("reading error");
        close(fd);
        return -2;
    }
    memcpy(&header, buffer, 2);
    //validating the version
    if (header.version < version_low || header.version > version_high)
    {
        if (!findall)
            printf("ERROR\nwrong version\n");
        close(fd);
        return -4;
    }
    //validating the section number
    if (header.sections_number < section_low || header.sections_number > section_high)
    {
        if (!findall)
            printf("ERROR\nwrong sect_nr\n");
        close(fd);
        return -5;
    }
    //reading the sections
    if (read(fd, &buffer, section_size * header.sections_number) != section_size * header.sections_number)
    {
        perror("reading error");
        close(fd);
        return -2;
    }
    //mapping the read content to a section header in order to ease field access
    header.sections = (Section_Header *)buffer;
    for (int i = 0; i < header.sections_number; i++)
    {
        //validating the type
        if (header.sections[i].type > max_type || !types[header.sections[i].type])
        {
            if (!findall)
                printf("ERROR\nwrong sect_types\n");
            close(fd);
            return -6;
        }
        //validating the size for findall case
        if (!extract && findall && header.sections[i].size > max_size)
        {
            close(fd);
            return 2;
        }
    }

    if (!findall)
    {   
        //printing the sections
        printf("SUCCESS\n");
        printf("version=%d\nnr_sections=%d\n", header.version, header.sections_number);
        for (int i = 0; i < header.sections_number; i++)
        {
            printf("section%d: %.13s %hu %u\n", i + 1, header.sections[i].name, header.sections[i].type, header.sections[i].size);
        }
    }
    //getting the offset and the size of the section that we want to extract
    if (extract)
    {
        if (section > 0 && section <= header.sections_number)
        {
            *offset = header.sections[section - 1].offset;
            *size = header.sections[section - 1].size;
        }
        else
        {
            close(fd);
            return 3;
        }
    }

    close(fd);
    return 0;
}
//extract option
int extract(const char *path, int section, int line)
{
    int offset = 0, size = 0;
    int parse_result = parse(path, TRUE, TRUE, section, &offset, &size);
    //checking if the file is valid
    if (parse_result < 0)
    {
        printf("ERROR\ninvalid file\n");
        return -1;
    }
    //checking if the given section is valid
    else if (parse_result == 3)
    {
        printf("ERROR\ninvalid section\n");
        return -2;
    }
    int fd = open(path, O_RDONLY);
    //mooving at the end of section
    lseek(fd, size + offset, SEEK_SET);
    char buffer[MAX_BUFF] = {'\0'};
    int size_left = size;
    int current_line = 1;
    // reading from the file either the size of the buffer characters or the remainding size
    int read_amount = MIN(PATH_MAX, size_left);
    //while we didn't read the entire section
    while (read_amount)
    {
        //reading from the end of the file read amount characters
        lseek(fd, -read_amount, SEEK_CUR);
        if (read(fd, buffer, read_amount) != read_amount)
        {
            perror("reading error");
            close(fd);
            return -3;
        }
        //treating the case when the searched line is the first
        if (line == 1)
        {
            printf("SUCCESS\n");
        }
        for (int i = read_amount - 1; i >= 0; i--)
        {
            // if we foudn a section separator we increase the line number
            if (buffer[i] == 0x0A)
            {
                current_line++;
                if (current_line == line)
                {
                    printf("SUCCESS\n");
                }
                else if (current_line > line)
                {
                    break;
                }
            }
            //if we are on the searched line we print the characters on it
            else if (current_line == line)
            {
                printf("%c", buffer[i]);
            }
        }
        //moving the the cursor at the begginign of the buffer and decrease the remainding size
        lseek(fd, -read_amount, SEEK_CUR);
        size_left -= read_amount;
        read_amount = MIN(PATH_MAX, size_left);
    }

    if (current_line < line)
    {
        printf("ERROR\ninvalid line\n");
        close(fd);
        return -3;
    }

    close(fd);
    return 0;
}
int findall(const char *path)
{
    //checking if the path is not secure
    if (strstr(path, ".."))
    {
        printf("ERROR\ninvalid directory path\n");
        return -1;
    }
    char full_path[PATH_MAX];
    DIR *dir = NULL;
    struct stat stat_buffer;
    struct dirent *entry = NULL;

    dir = opendir(path);
    //checking if the directory could open
    if (dir == NULL)
    {
        printf("ERROR\ninvalid directory path\n");
        return -1;
    }
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            //concatenating the path
            snprintf(full_path, PATH_MAX, "%s/%s", path, entry->d_name);
            if (lstat(full_path, &stat_buffer) == 0)
            {
                //checking if the current file is a directory ino order to explore it
                if (S_ISDIR(stat_buffer.st_mode))
                {
                    findall(full_path);
                }
                else if (S_ISREG(stat_buffer.st_mode))
                {
                    //if it's a regular file, we check if it's a valid SF file with no section that has the size greater than 1499
                    if (!parse(full_path, TRUE, FALSE, 0, NULL, NULL))
                    {
                        printf("%s\n", full_path);
                    }
                }
            }
        }
    }

    closedir(dir);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2)
    {
        char *path = NULL;
        char *option = NULL;
        int section = 0;
        int line = 0;
        int perms = 0;
        int size_greater = 0;
        bool recursive = FALSE;

        //traversing the arguments
        for (int i = 1; i < argc; i++)
        {
            //checking if an argument starts with path=
            if (strncmp(argv[i], "path=", 5) == 0)
            {
                //storing path's address
                path = argv[i] + 5;
            }
            else if (strcmp(argv[i], "recursive") == 0)
            {
                //setting the recursive flag to true
                recursive = TRUE;
            }
            else if (strncmp(argv[i], "permissions=", 12) == 0)
            {
                //storing the permissions as a number
                perms = extract_permisions(argv[i] + 12);
            }
            else if (strncmp(argv[i], "size_greater=", 13) == 0)
            {
                //parsing the size
                sscanf(argv[i] + 13, "%d", &size_greater);
                
            }
            else if (strncmp(argv[i], "section=", 8) == 0)
            {
                //storing the section
                sscanf(argv[i] + 8, "%d", &section);
            }
            else if (strncmp(argv[i], "line=", 5) == 0)
            {
                //storing the line
                sscanf(argv[i] + 5, "%d", &line);
            }
            else
            {
                option = argv[i];
            }
        }

        //list
        if (strcmp(option, "list") == 0)
        {
            if (list(path, recursive, perms, size_greater) == 0)
            {
                printf("SUCCESS\n");
                return 0;
            }
        }
        //parse
        else if (strcmp(option, "parse") == 0)
        {
            parse(path, FALSE, FALSE, 0, NULL, NULL);
            return 0;
        }
        //findall
        else if (strcmp(option, "findall") == 0)
        {
            if (findall(path) == 0)
            {
                printf("SUCCESS\n");
            }
            return 0;
        }
        //extract
        else if (strcmp(option, "extract") == 0)
        {
            if (extract(path, section, line) == 0)
            return 0;
        }
        //variant
        else if (strcmp(option, "variant") == 0)
        {
            printf("26376\n");
        }
    }

    return 0;
}