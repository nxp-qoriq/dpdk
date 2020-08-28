#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>

#include "qos.h"

/* trim leading and trailing spaces */
static void
trim_space(char *str)
{
        char *start, *end;

        for (start = str; *start; start++) {
                if (!isspace((unsigned char) start[0]))
                        break;
        }

        for (end = start + strlen(start); end > start + 1; end--) {
                if (!isspace((unsigned char) end[-1]))
                        break;
        }

        *end = 0;

        /* Shift from "start" to the beginning of the string */
        if (start > str)
                memmove(str, start, (end - start) + 1);
}

static int
parse_entry(struct qos_data *q, char *entry, struct sched_shaper_data *vector)
{
        int ret = 0;
        char *token, *key_token, *err = NULL;

        if (entry == NULL) {
                printf("Expected entry value\n");
                return -1;
        }

        /* get key */
        token = strtok(entry, ENTRY_DELIMITER);
        key_token = token;
        /* get values for key */
        token = strtok(NULL, ENTRY_DELIMITER);

        if (key_token == NULL || token == NULL) {
                printf("Expected 'key = values' but was '%.40s'..\n", entry);
                return -1;
        }
        trim_space(key_token);

	if (!strcmp(key_token, "ID")) {
                vector->id = strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
	} else if (!strcmp(key_token, "CIR")) {
                vector->cir_rate = strtof(token, &err);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
	} else if (!strcmp(key_token, "EIR")) {
                vector->eir_rate = strtof(token, &err);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
	} else if (!strcmp(key_token, "CIR_SIZE")) {
                vector->cir_burst_size = strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
	} else if (!strcmp(key_token, "EIR_SIZE")) {
                vector->eir_burst_size = strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
	} else if (!strcmp(key_token, "COUPLED")) {
                vector->coupled = strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
	} else if (!strcmp(key_token, "L2_ID")) {
                vector->l2_id = strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
	} else if (!strcmp(key_token, "PORT_IDX")) {
                vector->port_idx = strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
	} else if (!strcmp(key_token, "TAILDROP_TH")) {
                q->taildrop_th = strtoul(token, &err, 0);
                ret = ((err == NULL) || (*err != '\0')) ? -1 : 0;
	}

        return ret;
}

int
qos_data_read(const char *filename,
              struct qos_data *vector)
{
        int ret = 0;
        size_t len = 0;
	int l1 = 0, l2 = 0;
	struct sched_shaper_data *data = NULL;

        FILE *fp = NULL;
        char *line = NULL;
        char *entry = NULL;

        fp = fopen(filename, "r");
        if (fp == NULL) {
                printf("File %s does not exist\n", filename);
                return -1;
        }

        while (getline(&line, &len, fp) != -1) {

                /* ignore comments and new lines */
                if (line[0] == '#' || line[0] == '/' || line[0] == '\n'
                        || line[0] == '\r')
                        continue;

                trim_space(line);

                /* buffer for multiline */
                entry = realloc(entry, strlen(line) + 1);
                if (entry == NULL) {
                        printf("Fail to realloc %zu bytes\n", strlen(line) + 1);
                        ret = -1;
                        goto exit;
                }
		strcpy(entry, line);

                if (!strcmp(entry, "L1")) {
			if (l1 >= MAX_L1) {
				printf("only %d L1 scheduler supported\n", MAX_L1);
				goto exit;
			}
			data = &vector->l1[l1];
			l1++;
			continue;
		} else if (!strcmp(entry, "L2")) {
                        if (l2 >= MAX_L2) {
                                printf("only %d L2 scheduler supported\n", MAX_L2);
                                goto exit;
                        }
                        data = &vector->l2[l2];
                        l2++;
			continue;
		}
		if (!data) {
			printf("First keyword must be L1 or L2\n");
			goto exit;
		}

		/* FIXME: hardcodinng q_count */
		data->q_count = 1;
                if (entry[strlen(entry) - 1] == '=') {
                        if (getline(&line, &len, fp) != -1) {
                                trim_space(line);

                                /* extend entry about length of new line */
                                char *entry_extended = realloc(entry,
                                                strlen(line) +
                                                strlen(entry) + 1);

                                if (entry_extended == NULL) {
                                        printf("Fail to allocate %zu bytes\n",
                                                        strlen(line) +
                                                        strlen(entry) + 1);
                                        ret = -1;
                                        goto exit;
                                }

                                entry = entry_extended;
                                /* entry has been allocated accordingly */
                                strcpy(&entry[strlen(entry)], line);

                        }
                }
                ret = parse_entry(vector, entry, data);
                if (ret != 0) {
                        printf("An error occurred while parsing!\n");
                        goto exit;
                }
	}
	vector->l1_count = l1;
	vector->l2_count = l2;
exit:
	fclose(fp);
        free(line);
        free(entry);

        return ret;
}
