/*
 * mini_maze: учебный таргет-«лабиринт». Вход должен начинаться с магии "NEAT",
 * затем байт команды выбирает ветку разбора. В нескольких ветках спрятаны
 * детерминированные краши (abort, SIGFPE, NULL-разыменование, переполнение стека).
 * Читает файл из argv[1] или stdin.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 4096

static void crash_null(void) {
  volatile int *p = NULL;
  *p = 1;
}

static int recurse(int depth) {
  volatile char pad[256];
  pad[0] = (char)depth;
  return recurse(depth + 1) + pad[0];
}

static int cmd_word(const uint8_t *d, size_t n) {
  /* Посимвольное сравнение: каждый совпавший байт открывает новую ветку. */
  const char *word = "FUZZING";
  size_t i;
  for (i = 0; i < 7; i++) {
    if (i >= n) return (int)i;
    if (d[i] != (uint8_t)word[i]) return (int)i;
    switch (i) {
      case 0: puts("F"); break;
      case 1: puts("FU"); break;
      case 2: puts("FUZ"); break;
      case 3: puts("FUZZ"); break;
      case 4: puts("FUZZI"); break;
      case 5: puts("FUZZIN"); break;
      case 6: crash_null(); break;
    }
  }
  return 7;
}

static int cmd_div(const uint8_t *d, size_t n) {
  if (n < 2) return 0;
  if (d[1] != '/') return 1;
  int divisor = d[0] - '0';
  if (divisor < 0 || divisor > 9) return 2;
  volatile int r = 100 / divisor; /* d[0]=='0' -> SIGFPE */
  return r;
}

static int cmd_sum(const uint8_t *d, size_t n) {
  if (n < 8) return 0;
  unsigned sum = 0;
  size_t i;
  for (i = 0; i < n; i++) sum += d[i];
  if ((sum & 0xff) == 0x42) {
    if (d[0] == d[n - 1]) abort();
    return 2;
  }
  return 1;
}

static int cmd_digits(const uint8_t *d, size_t n) {
  int nines = 0, digits = 0;
  size_t i;
  for (i = 0; i < n; i++) {
    if (d[i] >= '0' && d[i] <= '9') {
      digits++;
      if (d[i] == '9') nines++;
    }
  }
  if (digits > 3) {
    if (nines > 4) return recurse(0); /* переполнение стека */
    return 2;
  }
  return 1;
}

static int process(const uint8_t *d, size_t n) {
  if (n < 4) return 0;
  if (d[0] != 'N') return 1;
  if (d[1] != 'E') return 2;
  if (d[2] != 'A') return 3;
  if (d[3] != 'T') return 4;
  if (n < 5) return 5;
  switch (d[4]) {
    case 'W': return cmd_word(d + 5, n - 5);
    case 'D': return cmd_div(d + 5, n - 5);
    case 'S': return cmd_sum(d + 5, n - 5);
    case '9': return cmd_digits(d + 5, n - 5);
    case 'E':
      if (n > 6 && d[5] == d[6]) return 10;
      return 11;
    default: return 6;
  }
}

int main(int argc, char **argv) {
  static uint8_t buf[MAX_INPUT];
  FILE *f = stdin;
  if (argc > 1) {
    f = fopen(argv[1], "rb");
    if (!f) return 1;
  }
  size_t n = fread(buf, 1, sizeof(buf), f);
  if (f != stdin) fclose(f);
  return process(buf, n) > 1000 ? 1 : 0;
}
