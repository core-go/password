package dynamodb

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	p "github.com/core-go/password"
	"strconv"
	"strings"
	"time"
)

type PasswordRepository struct {
	DB                *dynamodb.DynamoDB
	UserTableName     string
	PasswordTableName string
	HistoryTableName  string
	Key               string // User Id from context
	PasswordName      string
	ToAddressName     string
	ChangedTimeName   string
	FailCountName     string
	UserName          string
	ChangedByName     string
	HistoryName       string
	TimestampName     string
}

func NewPasswordRepository(dynamoDB *dynamodb.DynamoDB, userTableName, passwordTableName, historyTableName, key, passwordName, toAddress, userName, changedTimeName, failCountName, changedByName, historyName, timestampName string) *PasswordRepository {
	if len(passwordName) == 0 {
		passwordName = "password"
	}
	if len(toAddress) == 0 {
		toAddress = "email"
	}
	if len(userName) == 0 {
		userName = "username"
	}
	return &PasswordRepository{
		DB:                dynamoDB,
		UserTableName:     userTableName,
		PasswordTableName: passwordTableName,
		HistoryTableName:  historyTableName,
		Key:               key,
		ToAddressName:     toAddress,
		PasswordName:      passwordName,
		ChangedTimeName:   changedTimeName,
		FailCountName:     failCountName,
		UserName:          userName,
		ChangedByName:     changedByName,
		HistoryName:       historyName,
		TimestampName:     timestampName,
	}
}

func NewDefaultPasswordRepository(dynamoDB *dynamodb.DynamoDB, userTableName, passwordTableName, historyTableName, key, changedTimeName, failCountName string) *PasswordRepository {
	return NewPasswordRepository(dynamoDB, userTableName, passwordTableName, historyTableName, key, "password", "email", "username", changedTimeName, failCountName, "", "history", "timestamp")
}

func NewPasswordRepositoryByConfig(dynamoDB *dynamodb.DynamoDB, userTableName, passwordTableName, historyTableName string, key string, c p.PasswordSchemaConfig) *PasswordRepository {
	return NewPasswordRepository(dynamoDB, userTableName, passwordTableName, historyTableName, key, c.Password, c.ToAddress, c.Username, c.ChangedTime, c.FailCount, c.ChangedBy, c.History, c.Timestamp)
}

func (r *PasswordRepository) GetUserId(ctx context.Context, userName string) (string, error) {
	projection := expression.NamesList(expression.Name("_id"))
	filter := expression.Equal(expression.Name(r.UserName), expression.Value(userName))
	expr, _ := expression.NewBuilder().WithProjection(projection).WithFilter(filter).Build()
	query := &dynamodb.ScanInput{
		TableName:                 aws.String(r.UserTableName),
		ProjectionExpression:      expr.Projection(),
		FilterExpression:          expr.Filter(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}
	output, err := r.DB.ScanWithContext(ctx, query)
	if err != nil {
		return "", err
	}
	if len(output.Items) != 1 {
		return "", nil
	}
	var result map[string]string
	err = dynamodbattribute.UnmarshalMap(output.Items[0], &result)
	if err != nil {
		return "", err
	}
	return result["_id"], err
}

func (r *PasswordRepository) GetUser(ctx context.Context, userNameOrEmail string) (string, string, string, string, error) {
	projection := expression.NamesList(expression.Name("_id"), expression.Name(r.UserName), expression.Name(r.ToAddressName))
	userNameFilter := expression.Equal(expression.Name(r.UserName), expression.Value(userNameOrEmail))
	emailFilter := expression.Equal(expression.Name(r.ToAddressName), expression.Value(userNameOrEmail))
	filter := expression.Or(userNameFilter, emailFilter)
	expr, _ := expression.NewBuilder().WithProjection(projection).WithFilter(filter).Build()
	query := &dynamodb.ScanInput{
		TableName:                 aws.String(r.UserTableName),
		ProjectionExpression:      expr.Projection(),
		FilterExpression:          expr.Filter(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}
	output, err := r.DB.ScanWithContext(ctx, query)
	if err != nil || len(output.Items) == 0 {
		return "", "", "", "", err
	}

	var userResult map[string]string
	err = dynamodbattribute.UnmarshalMap(output.Items[0], &userResult)
	if err != nil {
		return "", "", "", "", err
	}

	userId := userResult["_id"]
	userName := userResult[r.UserName]
	email := userResult[r.ToAddressName]

	keyMap := map[string]*dynamodb.AttributeValue{}
	keyMap["_id"] = &dynamodb.AttributeValue{S: aws.String(userId)}
	input := &dynamodb.GetItemInput{
		TableName: aws.String(r.PasswordTableName),
		Key:       keyMap,
	}
	resp, err := r.DB.GetItemWithContext(ctx, input)
	if err != nil || len(resp.Item) == 0 {
		return "", "", "", "", err
	}

	var passResult map[string]string
	err = dynamodbattribute.UnmarshalMap(resp.Item, &passResult)
	return userId, userName, email, passResult[r.PasswordName], err
}

func (r *PasswordRepository) Update(ctx context.Context, userId string, newPassword string) (int64, error) {
	pass := make(map[string]*dynamodb.AttributeValue)
	pass["_id"] = &dynamodb.AttributeValue{S: aws.String(userId)}
	pass[r.PasswordName] = &dynamodb.AttributeValue{S: aws.String(newPassword)}
	if len(r.ChangedTimeName) > 0 {
		pass[r.ChangedTimeName] = &dynamodb.AttributeValue{S: aws.String(time.Now().Format(time.RFC3339))}
	}
	if len(r.FailCountName) > 0 {
		pass[r.FailCountName] = &dynamodb.AttributeValue{N: aws.String("0")}
	}
	if len(r.ChangedByName) > 0 {
		uid := getString(ctx, r.Key)
		if len(uid) > 0 {
			pass[r.ChangedByName] = &dynamodb.AttributeValue{S: aws.String(uid)}
		} else {
			pass[r.ChangedByName] = &dynamodb.AttributeValue{S: aws.String(userId)}
		}
	}
	expected := make(map[string]*dynamodb.ExpectedAttributeValue)
	expected["_id"] = &dynamodb.ExpectedAttributeValue{Value: &dynamodb.AttributeValue{S: aws.String(userId)}, Exists: aws.Bool(true)}

	params := &dynamodb.PutItemInput{
		TableName:              aws.String(r.PasswordTableName),
		Expected:               expected,
		Item:                   pass,
		ReturnConsumedCapacity: aws.String(dynamodb.ReturnConsumedCapacityTotal),
	}
	output, err := r.DB.PutItemWithContext(ctx, params)
	if err != nil {
		if strings.Index(err.Error(), "ConditionalCheckFailedException:") >= 0 {
			return 0, fmt.Errorf("object not found")
		}
		return 0, err
	}
	return int64(aws.Float64Value(output.ConsumedCapacity.CapacityUnits)), nil
}

func (r *PasswordRepository) UpdateWithCurrentPassword(ctx context.Context, userId string, currentPassword, newPassword string) (int64, error) {
	k1, err1 := r.Update(ctx, userId, newPassword)
	if err1 != nil {
		return 0, err1
	}

	history := make(map[string]*dynamodb.AttributeValue)
	history["_id"] = &dynamodb.AttributeValue{S: aws.String(userId)}
	history[r.PasswordName] = &dynamodb.AttributeValue{S: aws.String(newPassword)}
	history[r.TimestampName] = &dynamodb.AttributeValue{N: aws.String(strconv.Itoa(time.Now().Second()))}
	params := &dynamodb.PutItemInput{
		TableName:              aws.String(r.HistoryTableName),
		Item:                   history,
		ReturnConsumedCapacity: aws.String(dynamodb.ReturnConsumedCapacityTotal),
	}
	output, err2 := r.DB.PutItemWithContext(ctx, params)
	if err2 != nil {
		return 0, err2
	}
	return k1 + int64(aws.Float64Value(output.ConsumedCapacity.CapacityUnits)), nil
}

func (r *PasswordRepository) GetHistory(ctx context.Context, userId string, max int) ([]string, error) {
	history := make([]string, 0)
	projection := expression.NamesList(expression.Name(r.PasswordName))
	keyCondition := expression.KeyEqual(expression.Key("_id"), expression.Value(userId))
	expr, _ := expression.NewBuilder().WithProjection(projection).WithKeyCondition(keyCondition).Build()
	query := &dynamodb.QueryInput{
		TableName:                 aws.String(r.UserTableName),
		ProjectionExpression:      expr.Projection(),
		KeyConditionExpression:    expr.KeyCondition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Limit:                     aws.Int64(int64(max)),
		ScanIndexForward:          aws.Bool(false),
	}
	output, err := r.DB.QueryWithContext(ctx, query)
	if err != nil {
		return history, err
	}
	var result []map[string]string
	err = dynamodbattribute.UnmarshalListOfMaps(output.Items, &result)
	if err != nil {
		return history, err
	}
	for idx := range result {
		history = append(history, result[idx][r.PasswordName])
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
