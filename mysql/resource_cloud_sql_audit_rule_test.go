package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccCloudSQLAuditRule_basic(t *testing.T) {
	cloudSQLAuditRuleName := "tf-test-cloudSQLAuditRule"
	resourceName := "mysql_cloudSQLAuditRule.test"

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheckSkipNotGoogleCloudSQL(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccCloudSQLAuditRuleCheckDestroy(cloudSQLAuditRuleName),
		Steps: []resource.TestStep{
			{
				Config: testAccCloudSQLAuditRuleConfigBasic(cloudSQLAuditRuleName),
				Check: resource.ComposeTestCheckFunc(
					testAccCloudSQLAuditRuleExists(cloudSQLAuditRuleName),
					resource.TestCheckResourceAttr(resourceName, "name", cloudSQLAuditRuleName),
				),
			},
		},
	})
}

func testAccCloudSQLAuditRuleExists(cloudSQLAuditRuleName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ctx := context.Background()
		db, err := connectToMySQL(ctx, testAccProvider.Meta().(*MySQLConfiguration))
		if err != nil {
			return err
		}

		count, err := testAccGetCloudSQLAuditRuleGrantCount(cloudSQLAuditRuleName, db)

		if err != nil {
			return err
		}

		if count > 0 {
			return nil
		}

		return fmt.Errorf("no grants found for cloudSQLAuditRule %s", cloudSQLAuditRuleName)
	}
}

func testAccGetCloudSQLAuditRuleGrantCount(cloudSQLAuditRuleName string, db *sql.DB) (int, error) {
	rows, err := db.Query(fmt.Sprintf("SHOW GRANTS FOR '%s'", cloudSQLAuditRuleName))
	if err != nil {
		return 0, err
	}

	defer rows.Close()

	count := 0
	for rows.Next() {
		count++
	}

	return count, nil
}

func testAccCloudSQLAuditRuleCheckDestroy(cloudSQLAuditRuleName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ctx := context.Background()
		db, err := connectToMySQL(ctx, testAccProvider.Meta().(*MySQLConfiguration))
		if err != nil {
			return err
		}

		count, err := testAccGetCloudSQLAuditRuleGrantCount(cloudSQLAuditRuleName, db)
		if count > 0 {
			return fmt.Errorf("cloudSQLAuditRule %s still has grants/exists", cloudSQLAuditRuleName)
		}

		return nil
	}
}

func testAccCloudSQLAuditRuleConfigBasic(cloudSQLAuditRuleName string) string {
	return fmt.Sprintf(`
resource "mysql_cloud_sql_audit_rule" "test" {
  name = "%s"
}
`, cloudSQLAuditRuleName)
}
