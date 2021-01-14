/* 
 * This file is part of FPP (File Protection Program).
 *
 * See LICENSE for licensing information.
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

#if (_WIN32)
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include "getpass.h"

#if (_WIN32)

char *
fpp_getpass(const char *promt)
{
    size_t buf_size, i;
    char *buf, c;
    HANDLE hstdin;
    DWORD mode = 0;

    buf_size = FPP_PASSWORD_BUFSIZE;

    /* Turn echoing off*/
    hstdin = GetStdHandle(STD_INPUT_HANDLE); 

    GetConsoleMode(hstdin, &mode);
    SetConsoleMode(hstdin, mode & (~ENABLE_ECHO_INPUT));

    buf = malloc(buf_size * sizeof(char));
    if (!buf) {
        return NULL;
    }

    fprintf(stdout, "%s", promt);

    for (i = 0; i <= buf_size - 1; ++i) {
        c = getc(stdin);
        if (c == '\n' || c == '\0') {
            buf[i] = '\0';
            break;
        }
        if (i == (buf_size - 1)) {
            fprintf(stdout, "\n");
            free(buf);
            return NULL;
        }
        buf[i] = c;
    }

    buf[buf_size - 1] = '\0';
    fprintf(stdout, "\n");

    /* Restore terminal */
    SetConsoleMode(hstdin, mode);

    return buf;
}

#else

char *
fpp_getpass(const char *promt)
{
    size_t buf_size, i;
    struct termios old;
    struct termios new;
    char *buf, c;

    buf_size = FPP_PASSWORD_BUFSIZE;

    /* Turn echoing off */
    if (tcgetattr(STDIN_FILENO, &old) != 0) {
        return NULL;
    }

    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new) != 0) {
        return NULL;
    }

    buf = malloc(buf_size * sizeof(char));
    if (!buf) {
        return NULL;
    }

    fprintf(stdout, "%s", promt);

    for (i = 0; i <= buf_size - 1; ++i) {
        c = getc(stdin);
        if (c == '\n' || c == '\0') {
            buf[i] = '\0';
            break;
        }
        if (i == (buf_size - 1)) {
            fprintf(stdout, "\n");
            free(buf);
            return NULL;
        }
        buf[i] = c;
    }

    buf[buf_size - 1] = '\0';
    fprintf(stdout, "\n");

    /* Restore terminal */
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);

    return buf;
}

#endif
