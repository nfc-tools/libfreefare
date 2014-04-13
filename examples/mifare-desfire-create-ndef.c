/*-
 * Copyright (C) 2010, Audrey Diacre.
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
 *
 * $Id$
 */

#include "config.h"

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <freefare.h>

/*
 * This example was written based on information provided by the
 * following documents:
 *
 * AN11004 Mifare DESFire as Type 4 Tag
 * NFC Forum Type 4 Tag Extensions for Mifare DESFire
 * Rev. 1.1 - 21 August 2007
 * Rev. 2.2 - 4 January 2012
 *
 */


uint8_t key_data_picc[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t key_data_app[8]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

struct {
    bool interactive;
} create_options = {
    .interactive = true
};

static void
usage(char *progname)
{
    fprintf (stderr, "This application turns Mifare DESFire targets into NFC Forum Type 4 Tags.\n");
    fprintf (stderr, "usage: %s [-y] [-K 11223344AABBCCDD]\n", progname);
    fprintf (stderr, "\nOptions:\n");
    fprintf (stderr, "  -y     Do not ask for confirmation\n");
    fprintf (stderr, "  -K     Provide another PICC key than the default one\n");
}

int
main(int argc, char *argv[])
{
    int ch;
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    MifareTag *tags = NULL;

    while ((ch = getopt (argc, argv, "hyK:")) != -1) {
        switch (ch) {
        case 'h':
            usage(argv[0]);
            exit (EXIT_SUCCESS);
            break;
        case 'y':
            create_options.interactive = false;
            break;
        case 'K':
            if (strlen(optarg) != 16) {
                usage(argv[0]);
                exit (EXIT_FAILURE);
            }
            uint64_t n = strtoull(optarg, NULL, 16);
            int i;
            for (i=7; i>=0; i--) {
                key_data_picc[i] = (uint8_t) n;
                n >>= 8;
            }
            break;
        default:
            usage(argv[0]);
            exit (EXIT_FAILURE);
        }
    }
    // Remaining args, if any, are in argv[optind .. (argc-1)]

    nfc_connstring devices[8];
    size_t device_count;

    nfc_context *context;
    nfc_init (&context);
    if (context == NULL)
	errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

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
	    errx (EXIT_FAILURE, "Error listing tags.");
	}

	for (int i = 0; (!error) && tags[i]; i++) {
	    if (DESFIRE != freefare_get_tag_type (tags[i]))
		continue;

	    char *tag_uid = freefare_get_tag_uid (tags[i]);
	    char buffer[BUFSIZ];
	    int res;

	    res = mifare_desfire_connect (tags[i]);
	    if (res < 0) {
		warnx ("Can't connect to Mifare DESFire target.");
		error = EXIT_FAILURE;
		break;
	    }

	    // We've to track DESFire version as NDEF mapping is different
	    struct mifare_desfire_version_info info;
	    res = mifare_desfire_get_version (tags[i], &info);
	    if (res < 0) {
		freefare_perror (tags[i], "mifare_desfire_get_version");
		error = 1;
		break;
	    }

	    printf ("Found %s with UID %s and software v%d.%d\n", freefare_get_tag_friendly_name (tags[i]), tag_uid, info.software.version_major, info.software.version_minor);
	    bool create_ndef = true;
	    int ndef_mapping;
	    switch (info.software.version_major) {
	    case 0:
		ndef_mapping = 1;
		break;
	    case 1:
		ndef_mapping = 2;
		break;
	    default: // newer version? let's assume it supports latest mapping too
		warnx("Software version not supported. Assuming backward compatibility with version 1.");
		ndef_mapping = 2;
	    }
	    if (create_options.interactive) {
		printf ("Create NDEF app v%d [yN] ", ndef_mapping);
		fgets (buffer, BUFSIZ, stdin);
		create_ndef = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
	    } else {
		printf ("\n");
	    }

	    if (create_ndef) {

		/* Initialised Formatting Procedure. See section 6.5.1 and 8.1 of Mifare DESFire as Type 4 Tag document*/
		// Send Mifare DESFire Select Application with AID equal to 000000h to select the PICC level
		res = mifare_desfire_select_application(tags[i], NULL);
		if (res < 0)
		    errx (EXIT_FAILURE, "Application selection failed");

		MifareDESFireKey key_picc;
		MifareDESFireKey key_app;
		key_picc = mifare_desfire_des_key_new_with_version (key_data_picc);
		key_app  = mifare_desfire_des_key_new_with_version (key_data_app);

		// Authentication with PICC master key MAY be needed to issue ChangeKeySettings command
		res = mifare_desfire_authenticate (tags[i], 0, key_picc);
		if (res < 0)
		    errx (EXIT_FAILURE, "Authentication with PICC master key failed");

		MifareDESFireAID aid;
		if (ndef_mapping == 1) {
		    uint8_t key_settings;
		    uint8_t max_keys;
		    mifare_desfire_get_key_settings(tags[i], &key_settings,&max_keys);
		    if ((key_settings & 0x08) == 0x08){

			// Send Mifare DESFire ChangeKeySetting to change the PICC master key settings into :
			// bit7-bit4 equal to 0000b
			// bit3 equal to Xb, the configuration of the PICC master key MAY be changeable or frozen
			// bit2 equal to 0b, CreateApplication and DeleteApplication commands are allowed with PICC master key authentication
			// bit1 equal to 0b, GetApplicationIDs, and GetKeySettings are allowed with PICC master key authentication
			// bit0 equal to Xb, PICC masterkey MAY be frozen or changeable
			res = mifare_desfire_change_key_settings (tags[i],0x09);
			if (res < 0)
			    errx (EXIT_FAILURE, "ChangeKeySettings failed");
		    }
		    // Mifare DESFire Create Application with AID equal to EEEE10h, key settings equal to 0x09, NumOfKeys equal to 01h
		    aid = mifare_desfire_aid_new(0xEEEE10);
		    res = mifare_desfire_create_application (tags[i], aid, 0x09, 1);
		    if (res < 0)
			errx (EXIT_FAILURE, "Application creation failed. Try mifare-desfire-format before running %s.", argv[0]);
		    // Mifare DESFire SelectApplication (Select previously creates application)
		    res = mifare_desfire_select_application(tags[i], aid);
		    if (res < 0)
			errx (EXIT_FAILURE, "Application selection failed");
		    free (aid);
		    // Authentication with NDEF Tag Application master key (Authentication with key 0)
		    res = mifare_desfire_authenticate (tags[i], 0, key_app);
		    if (res < 0)
			errx (EXIT_FAILURE, "Authentication with NDEF Tag Application master key failed");
		    // Mifare DESFire ChangeKeySetting with key settings equal to 00001001b
		    res = mifare_desfire_change_key_settings (tags[i],0x09);
		    if (res < 0)
			errx (EXIT_FAILURE, "ChangeKeySettings failed");
		    // Mifare DESFire CreateStdDataFile with FileNo equal to 03h (CC File DESFire FID), ComSet equal to 00h,
		    // AccesRights equal to E000h, File Size bigger equal to 00000Fh
		    res = mifare_desfire_create_std_data_file(tags[i],0x03,MDCM_PLAIN,0xE000,0x00000F);
		    if (res < 0)
			errx (EXIT_FAILURE, "CreateStdDataFile failed");
		    // Mifare DESFire WriteData to write the content of the CC File with CClEN equal to 000Fh,
		    // Mapping Version equal to 10h,MLe equal to 003Bh, MLc equal to 0034h, and NDEF File Control TLV
		    // equal to T =04h, L=06h, V=E1 04 (NDEF ISO FID=E104h) 0E E0 (NDEF File size =3808 Bytes) 00 (free read access)
		    // 00 free write access
		    uint8_t capability_container_file_content[15] = {
			0x00, 0x0F,                 // CCLEN: Size of this capability container.CCLEN values are between 000Fh and FFFEh
			0x10,                       // Mapping version
			0x00, 0x3B,                 // MLe: Maximum data size that can be read using a single ReadBinary command. MLe = 000Fh-FFFFh
			0x00, 0x34,                 // MLc: Maximum data size that can be sent using a single UpdateBinary command. MLc = 0001h-FFFFh
			0x04, 0x06,                 // T & L of NDEF File Control TLV, followed by 6 bytes of V:
			0xE1, 0x04,                 //   File Identifier of NDEF File
			0x0E, 0xE0,                 //   Maximum NDEF File size of 3808 bytes
			0x00,                       //   free read access
			0x00                        //   free write acces
		    };
		    res = mifare_desfire_write_data(tags[i],0x03,0,sizeof(capability_container_file_content),capability_container_file_content);
		    if (res>0){
			// Mifare DESFire CreateStdDataFile with FileNo equal to 04h (NDEF FileDESFire FID), CmmSet equal to 00h, AccessRigths
			// equal to EEE0h, FileSize equal to 000EE0h (3808 Bytes)
			res = mifare_desfire_create_std_data_file(tags[i],0x04,MDCM_PLAIN,0xEEE0,0x000EE0);
			if (res < 0)
			    errx (EXIT_FAILURE, "CreateStdDataFile failed");
		    } else {
			errx (EXIT_FAILURE, "Write CC file content failed");
		    }
		}
		else if (ndef_mapping == 2) {
		    // Mifare DESFire Create Application with AID equal to 000001h, key settings equal to 0x0F, NumOfKeys equal to 01h,
		    // 2 bytes File Identifiers supported, File-ID equal to E110h
		    aid = mifare_desfire_aid_new(0x000001);
		    uint8_t app[] = {0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
		    res = mifare_desfire_create_application_iso (tags[i], aid, 0x0F, 0x21, 0, 0xE110, app, sizeof (app));
		    if (res < 0)
			errx (EXIT_FAILURE, "Application creation failed. Try mifare-desfire-format before running %s.", argv[0]);
		    // Mifare DESFire SelectApplication (Select previously creates application)
		    res = mifare_desfire_select_application(tags[i], aid);
		    if (res < 0)
			errx (EXIT_FAILURE, "Application selection failed");
		    free (aid);
		    // Authentication with NDEF Tag Application master key (Authentication with key 0)
		    res = mifare_desfire_authenticate (tags[i], 0, key_app);
		    if (res < 0)
			errx (EXIT_FAILURE, "Authentication with NDEF Tag Application master key failed");
		    // Mifare DESFire CreateStdDataFile with FileNo equal to 01h (DESFire FID), ComSet equal to 00h,
		    // AccesRights equal to E000h, File Size bigger equal to 00000Fh, ISO File ID equal to E103h
		    res = mifare_desfire_create_std_data_file_iso(tags[i],0x01,MDCM_PLAIN,0xE000,0x00000F,0xE103);
		    if (res < 0)
			errx (EXIT_FAILURE, "CreateStdDataFileIso failed");
		    // Mifare DESFire WriteData to write the content of the CC File with CClEN equal to 000Fh,
		    // Mapping Version equal to 20h,MLe equal to 003Bh, MLc equal to 0034h, and NDEF File Control TLV
		    // equal to T =04h, L=06h, V=E1 04 (NDEF ISO FID=E104h) 0xNNNN (NDEF File size = 0x0800/0x1000/0x1E00 bytes)
		    // 00 (free read access) 00 free write access
		    uint8_t capability_container_file_content[15] = {
			0x00, 0x0F,                 // CCLEN: Size of this capability container.CCLEN values are between 000Fh and FFFEh
			0x20,                       // Mapping version
			0x00, 0x3B,                 // MLe: Maximum data size that can be read using a single ReadBinary command. MLe = 000Fh-FFFFh
			0x00, 0x34,                 // MLc: Maximum data size that can be sent using a single UpdateBinary command. MLc = 0001h-FFFFh
			0x04, 0x06,                 // T & L of NDEF File Control TLV, followed by 6 bytes of V:
			0xE1, 0x04,                 //   File Identifier of NDEF File
			0x04, 0x00,                 //   Maximum NDEF File size of 1024 bytes
			0x00,                       //   free read access
			0x00                        //   free write acces
		    };
		    uint16_t ndefmaxsize = 0x0800;
		    uint16_t announcedsize = 1 << (info.software.storage_size >> 1);
		    if (announcedsize >= 0x1000)
			ndefmaxsize = 0x1000;
		    if (announcedsize >= 0x1E00)
			ndefmaxsize = 0x1E00;
		    capability_container_file_content[11] = ndefmaxsize >> 8;
		    capability_container_file_content[12] = ndefmaxsize & 0xFF;
		    res = mifare_desfire_write_data(tags[i],0x01,0,sizeof(capability_container_file_content),capability_container_file_content);
		    if (res>0){
			// Mifare DESFire CreateStdDataFile with FileNo equal to 02h (DESFire FID), CmmSet equal to 00h, AccessRigths
			// equal to EEE0h, FileSize equal to ndefmaxsize (0x000800, 0x001000 or 0x001E00)
			res = mifare_desfire_create_std_data_file_iso(tags[i],0x02,MDCM_PLAIN,0xEEE0,ndefmaxsize, 0xE104);
			if (res < 0)
			    errx (EXIT_FAILURE, "CreateStdDataFileIso failed");
		    } else {
			errx (EXIT_FAILURE, "Write CC file content failed");
		    }
		}
		mifare_desfire_key_free (key_picc);
		mifare_desfire_key_free (key_app);
	    }
	    mifare_desfire_disconnect (tags[i]);
	    free (tag_uid);
	}
	freefare_free_tags (tags);
	nfc_close (device);
    }
    nfc_exit (context);
    exit (error);
}
