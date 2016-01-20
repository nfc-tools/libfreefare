#include <cutter.h>

#include <freefare.h>
#include "freefare_internal.h"

#include "fixture.h"
#include "common/mifare_desfire_auto_authenticate.h"

#define cut_assert_success(last_command) \
    do { \
        cut_assert_equal_int (OPERATION_OK, mifare_desfire_last_picc_error (tag), cut_message ("PICC replied %s", mifare_desfire_error_lookup (mifare_desfire_last_picc_error (tag)))); \
        cut_assert_not_equal_int (-1, res, cut_message ("Wrong return value")); \
    } while (0)

void
test_mifare_desfire_ev1_iso(void)
{
    int res;

    mifare_desfire_auto_authenticate(tag, 0);

    res = mifare_desfire_format_picc(tag);
    cut_assert_equal_int(res, 0, cut_message("mifare_desfire_format_picc()"));

    MifareDESFireDF *dfs;
    size_t count;
    res = mifare_desfire_get_df_names(tag, &dfs, &count);
    cut_assert_equal_int(res, 0, cut_message("mifare_desfire_get_df_names()"));
    cut_assert_equal_int(count, 0, cut_message("Wrong DF count"));
    cut_assert_null(dfs, cut_message("DF should be NULL"));

    MifareDESFireAID aid = mifare_desfire_aid_new(0x111110);
    res = mifare_desfire_create_application_iso(tag, aid, 0xFF, 1, 0, 0x111F, NULL, 0);
    cut_assert_success("mifare_desfire_create_application_iso");
    free(aid);

    uint8_t app2[] = "App2";
    aid = mifare_desfire_aid_new(0x222220);
    res = mifare_desfire_create_application_iso(tag, aid, 0xFF, 1, 0, 0x222F, app2, sizeof(app2));
    cut_assert_success("mifare_desfire_create_application_iso");
    free(aid);

    uint8_t app3[] = "App3";
    aid = mifare_desfire_aid_new(0x333330);
    res = mifare_desfire_create_application_iso(tag, aid, 0xFF, 1, 0, 0x333F, app3, sizeof(app3));
    cut_assert_success("mifare_desfire_create_application_iso");
    free(aid);

    aid = mifare_desfire_aid_new(0x444440);
    res = mifare_desfire_create_application_iso(tag, aid, 0xFF, 1, 0, 0x111F, NULL, 0);
    cut_assert_equal_int(-1, res, cut_message("Should fail"));
    cut_assert_equal_int(DUPLICATE_ERROR, mifare_desfire_last_picc_error(tag), cut_message("Should be a duplicate error"));

    res = mifare_desfire_create_application_iso(tag, aid, 0xFF, 1, 0, 0x444F, app2, sizeof(app2));
    cut_assert_equal_int(-1, res, cut_message("Should fail"));
    cut_assert_equal_int(DUPLICATE_ERROR, mifare_desfire_last_picc_error(tag), cut_message("Should be a duplicate error"));
    free(aid);


    res = mifare_desfire_get_df_names(tag, &dfs, &count);
    cut_assert_equal_int(0, res, cut_message("mifare_desfire_get_df_names()"));
    cut_assert_equal_int(3, count, cut_message("Wrong DF count"));
    cut_assert_not_null(dfs, cut_message("DF should not be NULL"));

    cut_assert_equal_int(0x111110, dfs[0].aid, cut_message("Wrong value"));
    cut_assert_equal_int(0x111F, dfs[0].fid, cut_message("Wrong value"));
    cut_assert_equal_int(0, dfs[0].df_name_len, cut_message("Wrong value"));

    cut_assert_equal_int(0x222220, dfs[1].aid, cut_message("Wrong value"));
    cut_assert_equal_int(0x222F, dfs[1].fid, cut_message("Wrong value"));
    cut_assert_equal_int(sizeof(app2), dfs[1].df_name_len, cut_message("Wrong value"));
    cut_assert_equal_memory(app2, sizeof(app2), dfs[1].df_name, dfs[1].df_name_len, cut_message("Wrong value"));

    cut_assert_equal_int(0x333330, dfs[2].aid, cut_message("Wrong value"));
    cut_assert_equal_int(0x333F, dfs[2].fid, cut_message("Wrong value"));
    cut_assert_equal_int(sizeof(app3), dfs[2].df_name_len, cut_message("Wrong value"));
    cut_assert_equal_memory(app3, sizeof(app3), dfs[2].df_name, dfs[2].df_name_len, cut_message("Wrong value"));
    free(dfs);

    aid = mifare_desfire_aid_new(0x555550);
    res = mifare_desfire_create_application_iso(tag, aid, 0xff, 1, 1, 0x555F, NULL, 0);
    cut_assert_success("mifare_desfire_create_application_iso");

    res = mifare_desfire_select_application(tag, aid);
    cut_assert_success("mifare_desfire_select_application");

    res = mifare_desfire_create_std_data_file_iso(tag, 1, MDCM_PLAIN, 0xEEEE, 32, 0x1234);
    cut_assert_success("mifare_desfire_create_std_data_file_iso");

    res = mifare_desfire_create_backup_data_file_iso(tag, 2, MDCM_PLAIN, 0xEEEE, 32, 0x2345);
    cut_assert_success("mifare_desfire_create_std_data_file_iso");

    res = mifare_desfire_create_linear_record_file_iso(tag, 3, MDCM_PLAIN, 0xEEEE, 32, 10, 0x3456);
    cut_assert_success("mifare_desfire_create_linear_record_file_iso");

    res = mifare_desfire_create_cyclic_record_file_iso(tag, 4, MDCM_PLAIN, 0xEEEE, 32, 10, 0x4567);
    cut_assert_success("mifare_desfire_create_cyclic_record_file_iso");

    uint16_t *ids;
    res = mifare_desfire_get_iso_file_ids(tag, &ids, &count);
    cut_assert_success("mifare_desfire_get_iso_file_ids");

    cut_assert_equal_int(4, count, cut_message("Invalid file count"));
    cut_assert_equal_int(0x1234, ids[0], cut_message("Wrong file ID"));
    cut_assert_equal_int(0x2345, ids[1], cut_message("Wrong file ID"));
    cut_assert_equal_int(0x3456, ids[2], cut_message("Wrong file ID"));
    cut_assert_equal_int(0x4567, ids[3], cut_message("Wrong file ID"));
    free(ids);

    free(aid);

}
