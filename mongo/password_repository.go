package mongo

import (
	"context"
	"fmt"
	p "github.com/core-go/password"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"strings"
	"time"
)

type PasswordRepository struct {
	UserCollection     *mongo.Collection
	PasswordCollection *mongo.Collection
	HistoryCollection  *mongo.Collection
	Key                string // User Id from context
	PasswordName       string
	ToAddressName      string
	ChangedTimeName    string
	FailCountName      string
	Username           string
	ChangedByName      string
	HistoryName        string
	TimestampName      string
}

func NewPasswordRepository(db *mongo.Database, userCollectionName, passwordCollectionName, historyCollectionName, key, passwordName, toAddress, userName, changedTimeName, failCountName, changedByName, historyName, timestampName string) *PasswordRepository {
	passwordCollection := db.Collection(passwordCollectionName)
	userCollection := passwordCollection
	historyCollection := userCollection
	if passwordCollectionName != userCollectionName {
		userCollection = db.Collection(userCollectionName)
	}
	if historyCollectionName != userCollectionName {
		historyCollection = db.Collection(historyCollectionName)
	}
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
		UserCollection:     userCollection,
		PasswordCollection: passwordCollection,
		HistoryCollection:  historyCollection,
		Key:                key,
		ToAddressName:      toAddress,
		PasswordName:       passwordName,
		ChangedTimeName:    changedTimeName,
		FailCountName:      failCountName,
		Username:           userName,
		ChangedByName:      changedByName,
		HistoryName:        historyName,
		TimestampName:      timestampName,
	}
}

func NewDefaultPasswordRepository(db *mongo.Database, userCollection, passwordCollection, historyCollectionName, key, changedTimeName, failCountName string) *PasswordRepository {
	return NewPasswordRepository(db, userCollection, passwordCollection, historyCollectionName, key, "password", "email", "userName", changedTimeName, failCountName, "", "history", "timestamp")
}

func NewPasswordRepositoryByConfig(db *mongo.Database, userCollectionName, passwordCollectionName, historyCollectionName string, key string, c p.PasswordSchemaConfig) *PasswordRepository {
	return NewPasswordRepository(db, userCollectionName, passwordCollectionName, historyCollectionName, key, c.Password, c.ToAddress, c.Username, c.ChangedTime, c.FailCount, c.ChangedBy, c.History, c.Timestamp)
}

func (r *PasswordRepository) GetUserId(ctx context.Context, userName string) (string, error) {
	query := bson.M{r.Username: userName}
	x := r.UserCollection.FindOne(ctx, query)
	er1 := x.Err()
	if er1 != nil {
		if strings.Compare(fmt.Sprint(er1), "mongo: no documents in result") == 0 {
			return "", nil
		}
		return "", er1
	}
	k, er3 := x.DecodeBytes()
	if er3 != nil {
		return "", er3
	}
	userId := k.Lookup("_id").StringValue()
	return userId, nil
}

func (r *PasswordRepository) GetUser(ctx context.Context, userNameOrEmail string) (string, string, string, string, error) {
	query := bson.M{"$or": []bson.M{{r.Username: userNameOrEmail}, {r.ToAddressName: userNameOrEmail}}}
	x := r.UserCollection.FindOne(ctx, query)
	er1 := x.Err()
	if er1 != nil {
		if strings.Compare(fmt.Sprint(er1), "mongo: no documents in result") == 0 {
			return "", "", "", "", nil
		}
		return "", "", "", "", er1
	}
	k, er3 := x.DecodeBytes()
	if er3 != nil {
		return "", "", "", "", er3
	}
	userId := k.Lookup("_id").StringValue()
	userName := k.Lookup(r.Username).StringValue()
	email := k.Lookup(r.ToAddressName).StringValue()

	if r.HistoryCollection.Name() == r.UserCollection.Name() {
		history := make([]string, 0)
		rawValues, err := k.Lookup(r.HistoryName).Array().Values()
		if err != nil {
			return "", "", "", "", err
		}
		for i := range rawValues {
			if password, ok := rawValues[i].Document().Lookup(r.PasswordName).StringValueOK(); ok {
				history = append(history, password)
			}
		}
		ctx = context.WithValue(ctx, r.HistoryName, history)
	}

	if r.UserCollection.Name() == r.PasswordCollection.Name() {
		password := k.Lookup(r.PasswordName).StringValue()
		return userId, userName, email, password, nil
	}
	idQuery := bson.M{"_id": userId}
	y := r.PasswordCollection.FindOne(ctx, idQuery)
	er4 := y.Err()
	if er4 != nil {
		if strings.Compare(fmt.Sprint(er4), "mongo: no documents in result") == 0 {
			return userId, userName, email, "", nil
		}
		return userId, userName, email, "", er4
	}
	i, er5 := y.DecodeBytes()
	if er5 != nil {
		return userId, userName, email, "", er5
	}

	password := i.Lookup(r.PasswordName).StringValue()

	return userId, userName, email, password, nil
}

func (r *PasswordRepository) Update(ctx context.Context, userId string, newPassword string) (int64, error) {
	pass := make(map[string]interface{})
	pass["_id"] = userId
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
	idQuery := bson.M{"_id": userId}

	updateQuery := bson.M{
		"$set": pass,
	}
	result, err := r.PasswordCollection.UpdateOne(ctx, idQuery, updateQuery)
	if result.ModifiedCount > 0 {
		return result.ModifiedCount, err
	} else if result.UpsertedCount > 0 {
		return result.UpsertedCount, err
	} else {
		return result.MatchedCount, err
	}
}

func (r *PasswordRepository) UpdateWithCurrentPassword(ctx context.Context, userId string, currentPassword, newPassword string) (int64, error) {
	pass := make(map[string]interface{})
	pass["_id"] = userId
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
	idQuery := bson.M{"_id": userId}

	updateQuery := bson.M{
		"$set": pass,
		"$addToSet": bson.M{
			r.HistoryName: bson.M{r.PasswordName: currentPassword, r.TimestampName: time.Now()},
		},
	}
	result, err := r.HistoryCollection.UpdateOne(ctx, idQuery, updateQuery)
	if result.ModifiedCount > 0 {
		return result.ModifiedCount, err
	} else if result.UpsertedCount > 0 {
		return result.UpsertedCount, err
	} else {
		return result.MatchedCount, err
	}
}

func (r *PasswordRepository) GetHistory(ctx context.Context, userId string, max int) ([]string, error) {
	history := make([]string, 0)
	if ctx.Value(r.HistoryName) != nil {
		history = ctx.Value(r.HistoryName).([]string)
	} else {
		findOptions := options.FindOne()
		findOptions.SetProjection(map[string]int{r.HistoryName: 1, "_id": 0})
		query := bson.M{"_id": userId}
		x := r.PasswordCollection.FindOne(ctx, query, findOptions)
		er1 := x.Err()
		if er1 != nil {
			if strings.Compare(fmt.Sprint(er1), "mongo: no documents in result") == 0 {
				return history, nil
			}
			return history, er1
		}
		k, er2 := x.DecodeBytes()
		if er2 != nil {
			return history, er2
		}
		rawValue := k.Lookup(r.HistoryName)
		if rawValue.Type == bsontype.Array {
			// found column HistoryName
			rawValues, er3 := rawValue.Array().Values()
			if er3 != nil {
				return history, er3
			}
			for i := range rawValues {
				if password, ok := rawValues[i].Document().Lookup(r.PasswordName).StringValueOK(); ok {
					history = append(history, password)
				}
			}
		}
	}
	if len(history) > 0 {
		start := len(history) - 1 - max
		end := len(history) - 1
		if start < 0 {
			start = 0
		}
		return history[start:end], nil
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

