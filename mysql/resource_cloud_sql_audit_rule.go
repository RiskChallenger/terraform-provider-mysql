package mysql

import (
	"context"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceCloudSQLAuditRule() *schema.Resource {
	return &schema.Resource{
		CreateContext: CreateCloudSQLAuditRule,
		ReadContext:   ReadCloudSQLAuditRule,
		DeleteContext: DeleteCloudSQLAuditRule,

		Schema: map[string]*schema.Schema{
			"user": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"db": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"obj": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"ops": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"op_result": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice([]string{
					"S",
					"U",
					"B",
				}, false),
			},
		},
	}
}

func CreateCloudSQLAuditRule(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	db, err := getDatabaseFromMeta(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	cloudSQLAuditRuleUser := d.Get("user").(string)
	cloudSQLAuditRuleDb := d.Get("db").(string)
	cloudSQLAuditRuleObj := d.Get("obj").(string)
	cloudSQLAuditRuleOps := d.Get("ops").(string)
	cloudSQLAuditRuleOpResult := d.Get("op_result").(string)

	sql := fmt.Sprintf("CALL mysql.cloudsql_create_audit_rule('%s','%s','%s','%s','%s',1, @outval,@outmsg);",
		cloudSQLAuditRuleUser,
		cloudSQLAuditRuleDb,
		cloudSQLAuditRuleObj,
		cloudSQLAuditRuleOps,
		cloudSQLAuditRuleOpResult)
	log.Printf("[DEBUG] SQL: %s", sql)

	_, err = db.ExecContext(ctx, sql)
	if err != nil {
		return diag.Errorf("error creating cloudSQLAuditRule: %s", err)
	}

	sql = fmt.Sprintf("CALL mysql.cloudsql_list_audit_rule('*',@outval,@outmsg);")
	log.Printf("[DEBUG] SQL: %s", sql)

	rows, err := db.QueryContext(ctx, sql)
	if err != nil {
		return diag.Errorf("failed to read audit rules from DB: %v", err)
	}
	defer rows.Close()

	var auditRule int
	for rows.Next() {
		var id int
		var username string
		var dbname string
		var object string
		var operation string
		var op_result string
		err := rows.Scan(&id, &username, &dbname, &object, &operation, &op_result)
		if err != nil {
			return diag.Errorf("failed scanning audit rules: %v", err)
		}
		if username == cloudSQLAuditRuleUser && dbname == cloudSQLAuditRuleDb && operation == cloudSQLAuditRuleOps && op_result == cloudSQLAuditRuleOpResult && object == cloudSQLAuditRuleObj {
			auditRule = id
			break
		}
	}

	if rows.Err() != nil {
		return diag.Errorf("failed getting rows: %v", rows.Err())
	}

	d.SetId(fmt.Sprintf("%d", auditRule))

	return nil
}

func ReadCloudSQLAuditRule(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	db, err := getDatabaseFromMeta(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	sql := fmt.Sprintf("CALL mysql.cloudsql_list_audit_rule('%s',@outval,@outmsg);", d.Id())
	log.Printf("[DEBUG] SQL: %s", sql)

	rows, err := db.QueryContext(ctx, sql)
	if err != nil {
		return diag.Errorf("failed to read audit rules from DB: %v", err)
	}
	defer rows.Close()

	var id int
	var username string
	var dbname string
	var object string
	var operation string
	var op_result string
	for rows.Next() {

		err := rows.Scan(&id, &username, &dbname, &object, &operation, &op_result)
		if err != nil {
			return diag.Errorf("failed scanning audit rules: %v", err)
		}

		d.Set("user", username)
		d.Set("db", dbname)
		d.Set("obj", object)
		d.Set("ops", operation)
		d.Set("op_result", op_result)
		break
	}

	if rows.Err() != nil {
		return diag.Errorf("failed getting rows: %v", rows.Err())
	}

	if id == 0 {
		log.Printf("[WARN] CloudSQLAuditRule (%s) not found; removing from state", d.Id())
		d.SetId("")
		return nil
	}

	return nil
}

func DeleteCloudSQLAuditRule(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	db, err := getDatabaseFromMeta(ctx, meta)
	if err != nil {
		return diag.FromErr(err)
	}

	sql := fmt.Sprintf("CALL mysql.cloudsql_delete_audit_rule('%s',1,@outval,@outmsg);", d.Id())
	log.Printf("[DEBUG] SQL: %s", sql)

	_, err = db.ExecContext(ctx, sql)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}
