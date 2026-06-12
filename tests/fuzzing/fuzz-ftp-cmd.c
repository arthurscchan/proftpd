/*
 * ProFTPD - FTP server fuzzing testsuite
 * Copyright (c) 2021-2026 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "conf.h"

cmd_rec *make_ftp_cmd(pool *p, char *buf, size_t buflen, int flags);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pool *p = NULL;
  char *line, *ptr, *nl;
  cmd_rec *cmd;
  int flags = 0;

  line = (char *) malloc(size + 1);
  if (line == NULL) {
    return 0;
  }

  memcpy(line, data, size);
  line[size] = '\0';

  /* Mirror pr_cmd_read(): strip trailing CR/LF, then skip a leading CR. */
  nl = strchr(line, '\n');
  if (nl != NULL) {
    *nl = '\0';
  }
  nl = strchr(line, '\r');
  if (nl != NULL) {
    *nl = '\0';
  }

  ptr = line;
  if (*ptr == '\r') {
    ptr++;
  }

  if (*ptr) {
    if (strncasecmp(ptr, C_SITE, 4) == 0) {
      flags |= PR_STR_FL_PRESERVE_WHITESPACE;
    }

    p = make_sub_pool(NULL);
    if (p == NULL) {
      free(line);
      return 0;
    }

    cmd = make_ftp_cmd(p, ptr, strlen(ptr), flags);
    if (cmd != NULL) {
      pr_cmd_is_http(cmd);
      pr_cmd_is_ssh2(cmd);
      pr_cmd_is_smtp(cmd);
    }

    destroy_pool(p);
  }

  free(line);
  return 0;
}
