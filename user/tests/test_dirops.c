/**
 * Tests the directory operations
 * @author Judicael Briand
 */

#include <check.h>

START_TEST (create_file)
{
    ck_assert_int_eq(5, 5);
}
END_TEST

int main()
{
    Suite * s = suite_create("lists");
    TCase * tc = tcase_create("Core");
    SRunner * sr = srunner_create(s);

    suite_add_tcase(s, tc);
    tcase_add_test(tc, create_file);

    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr, CK_MINIMAL);
    srunner_free(sr);
    return 0;
}
