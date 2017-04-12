/*-
 * Copyright (C) 2015, Romain Tartiere.
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

#if defined(HAVE_CONFIG_H)
#  include "config.h"
#endif

#include <ctype.h>
#include <err.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(HAVE_SYS_ENDIAN_H)
#  include <sys/endian.h>
#endif

#if defined(HAVE_ENDIAN_H)
#  include <endian.h>
#endif

#if defined(HAVE_COREFOUNDATION_COREFOUNDATION_H)
#  include <CoreFoundation/CoreFoundation.h>
#endif

#include <nfc/nfc.h>

#include <freefare.h>
#include "../libfreefare/freefare_internal.h"

#define NDEF_BUFFER_SIZE 512

void
usage (char *progname)
{
    fprintf (stderr, "usage: %s [options]\n", progname);
    fprintf (stderr, "\nAvailable options:\n");
    fprintf (stderr, "  -o FILE  Write NDEF message to FILE\n");
}

int
main (int argc, char *argv[])
{
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;

    int ch;
    char *ndef_file = NULL;
    while ((ch = getopt (argc, argv, "o:")) != -1) {
	switch (ch) {
	case 'o':
	    ndef_file = optarg;
	    break;
	case '?':
	    usage (argv[0]);
	    exit (EXIT_FAILURE);
	}
    }

    nfc_connstring devices[8];

    size_t device_count;

    nfc_context *context;
    nfc_init (&context);
    if (context == NULL)
	errx (EXIT_FAILURE, "Unable to init libnfc (malloc)");

    device_count = nfc_list_devices (context, devices, 8);
    if (device_count <= 0)
	errx (EXIT_FAILURE, "No NFC device found.");

    for (size_t d = 0; d < device_count; d++) {
	device = nfc_open (context, devices[d]);
	if (!device) {
	    warnx ("nfc_open() failed.");
	    error = EXIT_FAILURE;
	    continue;
	}

	tags = freefare_get_tags (device);
	if (!tags) {
	    nfc_close (device);
	    errx (EXIT_FAILURE, "Error listing FeliCa tag.");
	}

	for (int i = 0; (!error) && tags[i]; i++) {
	    int block = 1;
	    uint8_t ndef_message[NDEF_BUFFER_SIZE];
	    int ndef_space_left = NDEF_BUFFER_SIZE;
	    uint8_t *p = ndef_message;
	    ssize_t s;

	    // FIXME Instead of reading as much as we can, we should read until end of NDEF record (if any is found).
	    while ((ndef_space_left >= 16) && (s = felica_read (tags[i], FELICA_SC_RO, block++, p, 16)) > 0) {
		p += s;
		ndef_space_left -= s;
	    }

	    size_t ndef_message_length = 0;

	    if ((ndef_message[0] & 0x80) == 0x80) {
		uint8_t *ndef_record;
		do {
		    ndef_record = ndef_message + ndef_message_length;

		    size_t ndef_record_length = 1 + 1 + ndef_record[1];
		    size_t payload_length;
		    size_t payload_length_length;

		    if (ndef_record[0] & 0x10) {
			/* Short record */
			payload_length = ndef_record[2];
			payload_length_length = 1;
		    } else {
			payload_length = be32toh ((uint32_t) ndef_record + 2);
			payload_length_length = 4;
		    }
		    ndef_record_length += payload_length_length;
		    ndef_record_length += payload_length;

		    if (ndef_record[0] & 0x08) {
			ndef_record_length += 2;
		    }

		    ndef_message_length += ndef_record_length;
		    if (ndef_message_length > NDEF_BUFFER_SIZE)
			errx (EXIT_FAILURE, "NDEF message truncated");

		} while ((ndef_record[0] & 0x40) != 0x40);
	    }

	    if (ndef_message_length == 0)
		errx (EXIT_FAILURE, "No NDEF message found");

	    FILE *f;
	    if (ndef_file)
		f = fopen (ndef_file, "w");
	    else
		f = stdout;

	    if (fwrite (ndef_message, ndef_message_length, 1, f) != 1)
		err (EXIT_FAILURE, "Can't write NDEF message");

	    fclose (f);
	}

	freefare_free_tags (tags);
	nfc_close (device);
    }
    exit(EXIT_SUCCESS);
}
