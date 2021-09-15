package cassandra

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	p "github.com/core-go/password"
	"github.com/gocql/gocql"
)

type PasswordRepository struct {
	Cassandra         *gocql.ClusterConfig
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

func NewPasswordRepository(db *gocql.ClusterConfig, userTableName, passwordTableName, historyTableName, key string, idName, passwordName, toAddress, userName, changedTimeName, failCountName, changedByName, historyName, timestampName string) *PasswordRepository {
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
	return &PasswordRepository{
		Cassandra:         db,
		Key:               key,
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

func NewPasswordRepositoryByConfig(db *gocql.ClusterConfig, userTableName, passwordTableName, historyTableName string, key string, c p.PasswordSchemaConfig) *PasswordRepository {
	return NewPasswordRepository(db, userTableName, passwordTableName, historyTableName, key, c.UserId, c.Password, c.ToAddress, c.UserName, c.ChangedTime, c.FailCount, c.ChangedBy, c.History, c.Timestamp)
}

func NewDefaultPasswordRepository(db *gocql.ClusterConfig, userTableName, passwordTableName, historyTableName, key string, userId, changedTimeName, failCountName string) *PasswordRepository {
	return NewPasswordRepository(db, userTableName, passwordTableName, historyTableName, key, userId, "password", "email", "username", changedTimeName, failCountName, "", "history", "timestamp")
}

func (r *PasswordRepository) GetUserId(ctx context.Context, userName string) (string, error) {
	var userId string
	session, er0 := r.Cassandra.CreateSession()
	if er0 != nil {
		return "", er0
	}
	query := fmt.Sprintf("select %s from %s where %s = ? ALLOW FILTERING", r.IdName, r.UserTableName, r.UserName)
	rows := session.Query(query, userName)
	for _, _ = range rows.Iter().Columns() {
		row := make(map[string]interface{})
		if !rows.Iter().MapScan(row) {
			return "", rows.Exec()
		}
		if id, ok := row[r.IdName]; ok {
			userId = id.(string)
		}
	}
	defer session.Close()
	return userId, nil
}

func (r *PasswordRepository) GetUser(ctx context.Context, userNameOrEmail string) (string, string, string, string, error) {
	log.Println("Password Repository GetUser")
	session, er0 := r.Cassandra.CreateSession()
	if er0 != nil {
		return "", "", "", "", er0
	}
	query1 := `SELECT * FROM %s WHERE %s = ? ALLOW FILTERING`
	queryUserName := fmt.Sprintf(query1, r.UserTableName, r.UserName)
	rowsUserName := session.Query(queryUserName, userNameOrEmail).Iter()
	var userId string
	var userName string
	var email string
	var password string
	for {
		// New map each iteration
		row := make(map[string]interface{})
		if !rowsUserName.MapScan(row) {
			break
		} else {
			if id, ok := row[r.IdName]; ok {
				userId = id.(string)
			}
			if username, ok := row[r.UserName]; ok {
				userName = username.(string)
			}
			if emailRow, ok := row[r.ToAddressName]; ok {
				email = emailRow.(string)
			}
			if password, ok := row[r.PasswordName]; ok {
				password = password.(string)
			}
		}
	}

	queryEmail := fmt.Sprintf(query1, r.UserTableName, r.ToAddressName)
	rowsEmail := session.Query(queryEmail, userNameOrEmail).Iter()
	for {
		// New map each iteration
		row1 := make(map[string]interface{})
		if !rowsEmail.MapScan(row1) {
			break
		} else {
			if id, ok := row1[r.IdName]; ok {
				userId = id.(string)
			}
			if username, ok := row1[r.UserName]; ok {
				userName = username.(string)
			}
			if emailRow, ok := row1[r.ToAddressName]; ok {
				email = emailRow.(string)
			}
			if password, ok := row1[r.PasswordName]; ok {
				password = password.(string)
			}
		}
	}
	if password == "" {
		query2 := `SELECT %s FROM %s WHERE %s = ? ALLOW FILTERING`
		queryPassword := fmt.Sprintf(query2, r.PasswordName, r.PasswordTableName, r.IdName)
		err2 := session.Query(queryPassword, userId).Scan(&password)
		if err2 != nil {
			return "", "", "", "", err2
		}
	}
	defer session.Close()
	return userId, userName, email, password, nil
}

func (r *PasswordRepository) Update(ctx context.Context, userId string, newPassword string) (int64, error) {
	session, er0 := r.Cassandra.CreateSession()
	if er0 != nil {
		return 0, er0
	}
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
	query := fmt.Sprintf("select count(*) from %s where %s = %s", r.PasswordTableName, r.IdName, "?")
	err1 := session.Query(query, userId).Scan(&count)
	if err1 != nil {
		return 0, err1
	}
	if count > 0 {
		query, values := BuildSave(pass, r.PasswordTableName, userId, r.IdName, r.BuildParam)
		result := session.Query(query, values...)
		if result.Exec() != nil {
			return 0, result.Exec()
		}
		r0 := int64(result.Attempts())
		return r0, nil
	}

	query1, values1 := BuildInsert1(pass, r.PasswordTableName, r.BuildParam)
	result1 := session.Query(query1, values1...)
	r1 := int64(result1.Attempts())
	defer session.Close()
	return r1, result1.Exec()
}

func (r *PasswordRepository) UpdateWithCurrentPassword(ctx context.Context, userId string, currentPassword, newPassword string) (int64, error) {
	session, er0 := r.Cassandra.CreateSession()
	if er0 != nil {
		return 0, er0
	}
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
	history := make(map[string]interface{})
	history[r.IdName] = userId
	history[r.PasswordName] = currentPassword
	history[r.TimestampName] = time.Now().Format("2006-01-02 15:04:05")
	if r.HistoryTableName == r.PasswordTableName {
		queryHistoryTable := fmt.Sprintf("UPDATE %s SET %s = '%s' , %s = %s + [('%s', '%s')] WHERE %s = ?", r.HistoryTableName, r.PasswordName, newPassword, r.HistoryName, r.HistoryName, history[r.PasswordName], history[r.TimestampName], r.IdName)
		log.Println("currentPassword", queryHistoryTable)
		result2 := session.Query(queryHistoryTable, userId)
		if result2.Exec() != nil {
			return 0, result2.Exec()
		}
		r2 := result2.Latency()
		return r2, nil
	} else {
		queryHistoryTable := fmt.Sprintf("UPDATE %s SET %s = %s + [('%s', '%s')] WHERE %s = ?", r.HistoryTableName, r.HistoryName, r.HistoryName, history[r.PasswordName], history[r.TimestampName], r.IdName)
		result2 := session.Query(queryHistoryTable, userId)
		if result2.Exec() != nil {
			return 0, result2.Exec()
		}
		queryPasswordTable := fmt.Sprintf("UPDATE %s SET %s = %s WHERE %s = ?", r.PasswordTableName, r.PasswordName, newPassword, r.IdName)
		result3 := session.Query(queryPasswordTable, userId)
		if result3.Exec() != nil {
			queryDelete := fmt.Sprintf("UPDATE %s SET %s = %s - [('%s', '%s')] WHERE %s = ?", r.HistoryTableName, r.HistoryName, r.HistoryName, history[r.PasswordName], history[r.TimestampName], r.IdName)
			result4 := session.Query(queryDelete, userId)
			if result4.Exec() != nil {
				return 0, result4.Exec()
			}
			return 0, result3.Exec()
		}
		r3 := result3.Latency()
		return r3, nil
	}
}

func (r *PasswordRepository) GetHistory(ctx context.Context, userId string, max int) ([]string, error) {
	history := make([]string, 0)

	// arr := make(map[string]interface{})
	session, er0 := r.Cassandra.CreateSession()
	if er0 != nil {
		return history, er0
	}
	query := `SELECT %s FROM %s WHERE %s = %s`
	query = fmt.Sprintf(query, r.HistoryName, r.HistoryTableName, r.IdName, "?")
	rows := session.Query(query, userId)
	col := rows.Iter().Columns()
	type historyStruct struct {
		password  string
		timestamp time.Time
	}
	row := make(map[string]interface{})
	date_sorted_reviews := make([]historyStruct, 0)
	for _, _ = range col {
		if !rows.Iter().MapScan(row) {
			break
		}
	}
	for _, v := range row[r.HistoryName].([]map[string]interface{}) {
		var tam historyStruct
		for k1, v1 := range v {
			if k1 == "password" {
				tam.password = v1.(string)
			}
			if k1 == "timestamp" {
				tam.timestamp = v1.(time.Time)
			}
		}
		date_sorted_reviews = append(date_sorted_reviews, tam)
	}
	defer rows.Iter().Close()
	sort.Slice(date_sorted_reviews, func(i, j int) bool {
		return date_sorted_reviews[i].timestamp.After(date_sorted_reviews[j].timestamp)
	})
	for k, v := range date_sorted_reviews {
		history = append(history, v.password)
		if k >= 5 {
			break
		}
	}
	return history, nil
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

func BuildInsert1(model map[string]interface{}, table string, buildParam func(int) string) (string, []interface{}) {
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

func buildParametersFrom(i int, numCol int, buildParam func(int) string) string {
	var arrValue []string
	for j := 0; j < numCol; j++ {
		arrValue = append(arrValue, buildParam(i+j+1))
	}
	return strings.Join(arrValue, ",")
}
