package sql

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	p "github.com/common-go/password"
)

type PasswordRepository struct {
	Database          *sql.DB
	UserTableName     string
	PasswordTableName string
	HistoryTableName  string
	Key               string // User Id from context
	IdName            string
	PasswordName      string
	ToAddressName     string
	ChangedTimeName   string
	FailCountName     string
	UserName          string
	ChangedByName     string
	HistoryName       string
	TimestampName     string
	BuildParam        func(int) string
}

func NewPasswordRepositoryByConfig(db *sql.DB, userTableName, passwordTableName, historyTableName string, key string, c p.PasswordSchemaConfig) *PasswordRepository {
	return NewPasswordRepository(db, userTableName, passwordTableName, historyTableName, key, c.UserId, c.Password, c.ToAddress, c.UserName, c.ChangedTime, c.FailCount, c.ChangedBy, c.History, c.Timestamp)
}

func NewDefaultPasswordRepository(db *sql.DB, userTableName, passwordTableName, historyTableName, key string, userId, changedTimeName, failCountName string) *PasswordRepository {
	return NewPasswordRepository(db, userTableName, passwordTableName, historyTableName, key, userId, "password", "email", "username", changedTimeName, failCountName, "", "history", "timestamp")
}

func NewPasswordRepository(db *sql.DB, userTableName, passwordTableName, historyTableName, key string, idName, passwordName, toAddress, userName, changedTimeName, failCountName, changedByName, historyName, timestampName string) *PasswordRepository {
	if len(passwordName) == 0 {
		passwordName = "password"
	}
	if len(toAddress) == 0 {
		toAddress = "email"
	}
	if len(userName) == 0 {
		userName = "username"
	}
	if len(idName) == 0 {
		idName = "userid"
	}
	build := getBuild(db)
	return &PasswordRepository{
		Database:          db,
		Key:               key,
		BuildParam:        build,
		UserTableName:     strings.ToLower(userTableName),
		PasswordTableName: strings.ToLower(passwordTableName),
		HistoryTableName:  strings.ToLower(historyTableName),
		IdName:            strings.ToLower(idName),
		PasswordName:      strings.ToLower(passwordName),
		ToAddressName:     strings.ToLower(toAddress),
		ChangedTimeName:   strings.ToLower(changedTimeName),
		FailCountName:     strings.ToLower(failCountName),
		UserName:          strings.ToLower(userName),
		ChangedByName:     strings.ToLower(changedByName),
		HistoryName:       strings.ToLower(historyName),
		TimestampName:     strings.ToLower(timestampName),
	}
}

func (r *PasswordRepository) GetUserId(ctx context.Context, userName string) (string, error) {
	var userId []string
	query := fmt.Sprintf("select distinct `%s` from %s where %s = %s", r.IdName, r.UserTableName, r.UserName, r.BuildParam(0))
	rows, err := r.Database.Query(query, userName)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		if err1 := rows.Scan(&userId); err1 != nil {
			return "", err
		}
	}
	if err != nil {
		return "", err
	}

	return userId[0], nil
}

func (r *PasswordRepository) GetUser(ctx context.Context, userNameOrEmail string) (string, string, string, string, error) {
	arr := make(map[string]interface{})
	var query string
	query1 := `SELECT us.%s, us.%s, us.%s, au.%s
					FROM %s AS us INNER JOIN %s AS au ON us.%s = au.%s
					WHERE us.%s = %s or us.%s = %s`

	query2 := `SELECT us.%s, us.%s, us.%s, us.%s
					FROM %s AS us
					WHERE us.%s = %s or us.%s = %s`
	if r.PasswordTableName != r.UserTableName {
		query = fmt.Sprintf(query1, r.IdName, r.UserName, r.ToAddressName, r.PasswordName, r.UserTableName, r.PasswordTableName, r.IdName, r.IdName, r.UserName,
			r.BuildParam(0),
			r.ToAddressName,
			r.BuildParam(1),
		)
	} else {
		query = fmt.Sprintf(query2, r.IdName, r.UserName, r.ToAddressName, r.PasswordName, r.UserTableName, r.UserName,
			r.BuildParam(0),
			r.ToAddressName,
			r.BuildParam(1),
		)
	}
	rows, err := r.Database.Query(query, userNameOrEmail, userNameOrEmail)
	if err != nil {
		return "", "", "", "", err
	}
	//dont forget to close
	defer rows.Close()
	cols, _ := rows.Columns()
	for rows.Next() {
		columns := make([]interface{}, len(cols))
		columnPointers := make([]interface{}, len(cols))
		for i, _ := range columns {
			columnPointers[i] = &columns[i]
		}

		if err1 := rows.Scan(columnPointers...); err1 != nil {
			return "", "", "", "", err1
		}

		for i, colName := range cols {
			val := columnPointers[i].(*interface{})
			arr[colName] = *val
		}
	}

	err2 := rows.Err()
	if err2 != nil {
		return "", "", "", "", err2
	}

	if len(arr) == 0 {
		return "", "", "", "", nil
	}

	userId := string(arr[r.IdName].([]byte))
	userName := string(arr[r.UserName].([]byte))
	email := string(arr[r.ToAddressName].([]byte))
	password := string(arr[r.PasswordName].([]byte))
	return userId, userName, email, password, nil
}

func (r *PasswordRepository) Update(ctx context.Context, userId string, newPassword string) (int64, error) {
	pass := make(map[string]interface{})
	pass[r.IdName] = userId
	pass[r.PasswordName] = newPassword
	if len(r.ChangedTimeName) > 0 {
		pass[r.ChangedTimeName] = time.Now()
	}
	if len(r.FailCountName) > 0 {
		pass[r.FailCountName] = 0
	}
	if len(r.ChangedByName) > 0 {
		uid := getString(ctx, r.Key)
		if len(uid) > 0 {
			pass[r.ChangedByName] = uid
		} else {
			pass[r.ChangedByName] = userId
		}
	}

	var count int
	query := fmt.Sprintf("select count(*) from %s where %s = %s", r.PasswordTableName, r.IdName, r.BuildParam(0))
	rows, err0 := r.Database.Query(query, userId)
	if err0 != nil {
		return 0, err0
	}
	defer rows.Close()
	for rows.Next() {
		if err1 := rows.Scan(&count); err1 != nil {
			return 0, err1
		}
		break
	}
	tx, err1 := r.Database.Begin()
	if err1 != nil {
		return 0, err1
	}
	if count > 0 {
		query, values := BuildSave(pass, r.PasswordTableName, userId, r.IdName, r.BuildParam)
		result1, err3 := tx.Exec(query, values...)
		if err3 != nil {
			tx.Rollback()
			return 0, err3
		}
		if err4 := tx.Commit(); err4 != nil {
			tx.Rollback()
			return 0, err4
		}
		r, err5 := result1.RowsAffected()
		return r, err5
	}

	query1, values1 := BuildInsert(pass, r.PasswordTableName, r.BuildParam)
	result2, err3 := tx.Exec(query1, values1...)
	if err3 != nil {
		tx.Rollback()
		return 0, err3
	}
	if err4 := tx.Commit(); err4 != nil {
		tx.Rollback()
		return 0, err4
	}
	r1, err5 := result2.RowsAffected()
	return r1, err5
}

func (r *PasswordRepository) UpdateWithCurrentPassword(ctx context.Context, userId string, currentPassword, newPassword string) (int64, error) {
	pass := make(map[string]interface{})
	pass[r.IdName] = userId
	pass[r.PasswordName] = newPassword
	if len(r.ChangedTimeName) > 0 {
		pass[r.ChangedTimeName] = time.Now()
	}
	if len(r.FailCountName) > 0 {
		pass[r.FailCountName] = 0
	}
	if len(r.ChangedByName) > 0 {
		uid := getString(ctx, r.Key)
		if len(uid) > 0 {
			pass[r.ChangedByName] = uid
		} else {
			pass[r.ChangedByName] = userId
		}
	}

	var count int
	query := fmt.Sprintf("select count(*) from %s where %s = %s", r.PasswordTableName, r.IdName, r.BuildParam(0))
	rows, err0 := r.Database.Query(query, userId)
	if err0 != nil {
		return 0, err0
	}
	defer rows.Close()
	for rows.Next() {
		if err1 := rows.Scan(&count); err1 != nil {
			return 0, err1
		}
		break
	}
	tx, err1 := r.Database.Begin()
	if err1 != nil {
		return 0, err1
	}
	var result1 sql.Result
	if count > 0 {
		query, values := BuildSave(pass, r.PasswordTableName, userId, r.IdName, r.BuildParam)
		result0, err3 := tx.Exec(query, values...)
		result1 = result0
		if err3 != nil {
			tx.Rollback()
			return 0, err3
		}
	} else {
		query, values := BuildInsert(pass, r.PasswordTableName, r.BuildParam)
		result0, err4 := tx.Exec(query, values...)
		result1 = result0
		if err4 != nil {
			tx.Rollback()
			return 0, err4
		}
	}

	history := make(map[string]interface{})
	history[r.IdName] = userId
	history[r.PasswordName] = currentPassword
	history[r.TimestampName] = time.Now()
	query, value := BuildInsertHistory(r.HistoryTableName, history, r.BuildParam)
	result2, err5 := tx.Exec(query, value...)
	if err5 != nil {
		tx.Rollback()
		return 0, err5
	}
	if err6 := tx.Commit(); err6 != nil {
		tx.Rollback()
		return 0, err6
	}
	r1, err7 := result1.RowsAffected()
	if err7 != nil {
		tx.Rollback()
		return 0, err7
	}
	r2, err8 := result2.RowsAffected()
	if err7 != nil {
		tx.Rollback()
		return 0, err8
	}
	return r1 + r2, nil
}

func (r *PasswordRepository) GetHistory(ctx context.Context, userId string, max int) ([]string, error) {
	history := make([]string, 0)

	arr := make(map[string]interface{})
	query := `SELECT %s FROM %s WHERE %s = %s ORDER BY %s desc LIMIT %d OFFSET 1`
	query = fmt.Sprintf(query, r.PasswordName, r.HistoryTableName, r.IdName, r.BuildParam(0), r.TimestampName, max)
	rows, err := r.Database.Query(query, userId)
	if err != nil {
		return history, err
	}
	//dont forget to close
	defer rows.Close()
	cols, _ := rows.Columns()
	for rows.Next() {
		columns := make([]interface{}, len(cols))
		columnPointers := make([]interface{}, len(cols))
		for i, _ := range columns {
			columnPointers[i] = &columns[i]
		}

		if err1 := rows.Scan(columnPointers...); err1 != nil {
			return history, err1
		}

		for i, colName := range cols {
			val := columnPointers[i].(*interface{})
			arr[colName] = *val
		}

		if rows.Err() != nil {
			return history, rows.Err()
		}

		if len(arr) == 0 {
			return history, nil
		}
		history = append(history, string(arr[r.PasswordName].([]byte)))
	}
	return history, nil
}

func BuildSave(model map[string]interface{}, table string, id interface{}, idname string, buildParam func(int) string) (string, []interface{}) {
	colNumber := 0
	var values []interface{}
	querySet := make([]string, 0)
	for colName, v2 := range model {
		values = append(values, v2)
		querySet = append(querySet, fmt.Sprintf("%v="+buildParam(colNumber), colName))
		colNumber++
	}
	values = append(values, id)
	queryWhere := fmt.Sprintf(" %s = %s",
		idname,
		buildParam(colNumber),
	)
	query := fmt.Sprintf("update %v set %v where %v", table, strings.Join(querySet, ","), queryWhere)
	return query, values
}
func BuildInsert(model map[string]interface{}, table string, buildParam func(int) string) (string, []interface{}) {
	var cols []string
	var values []interface{}
	for columnName, value := range model {
		cols = append(cols, columnName)
		values = append(values, value)
	}
	column := fmt.Sprintf("(%v)", strings.Join(cols, ","))
	numCol := len(cols)
	value := fmt.Sprintf("(%v)", buildParametersFrom(0, numCol, buildParam))
	return fmt.Sprintf("insert into %v %v values %v", table, column, value), values
}
func BuildInsertHistory(tableName string, history map[string]interface{}, buildParam func(int) string) (string, []interface{}) {
	var cols []string
	var values []interface{}
	for col, v := range history {
		cols = append(cols, col)
		values = append(values, v)
	}
	column := fmt.Sprintf("(%v)", strings.Join(cols, ","))
	numCol := len(cols)
	value := fmt.Sprintf("(%v)", buildParametersFrom(0, numCol, buildParam))
	return fmt.Sprintf("INSERT INTO %v %v VALUES %v", tableName, column, value), values
}

func getString(ctx context.Context, key string) string {
	if len(key) > 0 {
		u := ctx.Value(key)
		if u != nil {
			s, ok := u.(string)
			if ok {
				return s
			} else {
				return ""
			}
		}
	}
	return ""
}

func buildParametersFrom(i int, numCol int, buildParam func(int) string) string {
	var arrValue []string
	for j := 0; j < numCol; j++ {
		arrValue = append(arrValue, buildParam(i+j+1))
	}
	return strings.Join(arrValue, ",")
}

func buildParam(i int) string {
	return "?"
}
func buildOracleParam(i int) string {
	return ":val" + strconv.Itoa(i)
}
func buildMsSqlParam(i int) string {
	return "@p" + strconv.Itoa(i)
}
func buildDollarParam(i int) string {
	return "$" + strconv.Itoa(i)
}
func getBuild(db *sql.DB) func(i int) string {
	driver := reflect.TypeOf(db.Driver()).String()
	switch driver {
	case "*pq.Driver":
		return buildDollarParam
	case "*godror.drv":
		return buildOracleParam
	case "*mssql.Driver":
		return buildMsSqlParam
	default:
		return buildParam
	}
}
