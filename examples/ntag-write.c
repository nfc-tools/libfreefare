/*-
 * Copyright (C) 2012, 2017 Romain Tartiere, Martin Dagarin (SloCompTech).
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
#include <err.h>
#include <stdlib.h>

#include <nfc/nfc.h>

#include <freefare.h>


int
main(int argc, char *argv[])
{
  int error = EXIT_SUCCESS;
  nfc_device *device = NULL;
  FreefareTag *tags = NULL;

  if (argc > 1)
	 errx(EXIT_FAILURE, "usage: %s", argv[0]);

  nfc_connstring devices[8];
  size_t device_count;

  nfc_context *context;
  nfc_init(&context);
  if (context == NULL)
	 errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

  device_count = nfc_list_devices(context, devices, sizeof (devices) / sizeof (*devices));
  if (device_count <= 0)
	 errx(EXIT_FAILURE, "No NFC device found");

  for (size_t d = 0; d < device_count; d++) {
   if (!(device = nfc_open(context, devices[d]))) {
    warnx("nfc_open() failed.");
    error = EXIT_FAILURE;
    continue;
	 }

    if (!(tags = freefare_get_tags(device))) {
      nfc_close(device);
      errx(EXIT_FAILURE, "Error listing tags.");
  	}

  	for (int i = 0; (!error) && tags[i]; i++) {
      switch (freefare_get_tag_type(tags[i])) {
      case NTAG_21x:
        break;
      default:
        continue;
      }

      char *tag_uid = freefare_get_tag_uid(tags[i]);
      printf("Tag with UID %s is a %s\n", tag_uid, freefare_get_tag_friendly_name (tags[i]));
      FreefareTag tag = tags[i];
      int res;
      if (ntag21x_connect(tag) < 0)
  		    errx(EXIT_FAILURE, "Error connecting to tag.");

      uint8_t data [4] = {0xfa,0xca,0xac,0xad}; // Data to write on tag
      uint8_t read[4]; // Buffer for reading data from tag

      bool flag_match = true;
      switch (true) {
      case true:
        /*
          Get information about tag
          MUST do, because here we are recognizing tag subtype (NTAG213,NTAG215,NTAG216), and gathering all parameters
        */
        res = ntag21x_get_info(tag);
        if(res < 0) {
          printf("Error getting info from tag\n");
          break;
        }

        // writing to tag 4 bytes on page 0x27 (check specs for NTAG21x before changing page number !!!)
        res = ntag21x_write(tag,0x27,data);
        if(res < 0) {
          printf("Error writing to tag\n");
          break;
        }
        res = ntag21x_fast_read4(tag,0x27,read); // Reading page from tag (4 bytes), you can also use ntag21x_read4 or ntag21x_read (16 bytes) or ntag21x_fast_read (start_page to end_page)
        if(res < 0) {
          printf("Error reading tag\n");
          break;
        }
        for(int i=0;i < 4;i++) // Checking if we can read what we have written earlyer
          if(data[i] != read[i]) {
            flag_match = false;
            break;
          }
        if(!flag_match)
          printf("Data don't match\n");
        else
          printf("Data match\n");
      }
        ntag21x_disconnect(tag);
        free(tag_uid);
    }
  	freefare_free_tags(tags);
  	nfc_close(device);
  }
  nfc_exit(context);
  exit(error);
}
