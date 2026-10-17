/*
 * mini_tlv: учебный таргет-парсер записей TLV (type, length, value).
 * Ближе к «настоящим» форматам: заголовок с версией, цикл по записям, проверки длины.
 * Баги: запись по неправильному индексу (NULL), abort при «невозможном» состоянии.
 * Читает файл из argv[1] или stdin.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 4096

struct state {
  int version;
  int records;
  int has_name;
  int has_data;
  char name[16];
  int *table;
};

static int rec_name(struct state *s, const uint8_t *v, uint8_t len) {
  if (len == 0) return 0;
  if (len > 15) len = 15;
  memcpy(s->name, v, len);
  s->name[len] = 0;
  s->has_name = 1;
  if (strcmp(s->name, "admin") == 0) return 2;
  return 1;
}

static int rec_data(struct state *s, const uint8_t *v, uint8_t len) {
  if (!s->has_name) return 0;
  if (len < 2) return 1;
  s->has_data = 1;
  if (v[0] == 0xde && v[1] == 0xad) {
    /* «таблица» создаётся только для version >= 2 — иначе NULL-разыменование */
    if (s->version >= 2) s->table = calloc(16, sizeof(int));
    s->table[v[1] & 0xf] = 1;
    free(s->table);
    s->table = NULL;
    return 3;
  }
  return 2;
}

static int rec_check(struct state *s, const uint8_t *v, uint8_t len) {
  if (len != 4) return 0;
  uint32_t x = (uint32_t)v[0] | ((uint32_t)v[1] << 8) | ((uint32_t)v[2] << 16) |
               ((uint32_t)v[3] << 24);
  if (x == 0x1337c0de) {
    if (s->has_name && s->has_data && s->records > 2) abort();
    return 2;
  }
  return 1;
}

static int parse(const uint8_t *d, size_t n) {
  struct state s;
  memset(&s, 0, sizeof(s));
  if (n < 3) return 0;
  if (d[0] != 'T' || d[1] != 'L') return 1;
  s.version = d[2];
  if (s.version == 0 || s.version > 3) return 2;
  size_t pos = 3;
  while (pos + 2 <= n) {
    uint8_t type = d[pos], len = d[pos + 1];
    pos += 2;
    if (pos + len > n) return 3;
    const uint8_t *v = d + pos;
    switch (type) {
      case 1: rec_name(&s, v, len); break;
      case 2: rec_data(&s, v, len); break;
      case 3: rec_check(&s, v, len); break;
      case 4:
        if (len > 0 && v[0] == 'Z') s.version = 1;
        break;
      default: return 4;
    }
    s.records++;
    pos += len;
  }
  return 5;
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
  parse(buf, n);
  return 0;
}
