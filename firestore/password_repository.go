package firestore

import (
	"cloud.google.com/go/firestore"
	"context"
	"fmt"
	p "github.com/core-go/password"
	"google.golang.org/api/iterator"
	"strings"
	"time"
)

type PasswordRepository struct {
	Client             *firestore.Client
	UserCollection     *firestore.CollectionRef
	PasswordCollection *firestore.CollectionRef
	HistoryCollection  *firestore.CollectionRef
	Key                string // User Id from context
	IdName             string
	PasswordName       string
	ToAddressName      string
	ChangedTimeName    string
	FailCountName      string
	Username           string
	ChangedByName      string
	TimestampName      string
}

func NewDefaultPasswordRepository(client *firestore.Client, userCollection, passwordCollection, historyCollectionName, key string, userId, userName, toAddress, changedTimeName, failCountName string) *PasswordRepository {
	if len(toAddress) == 0 {
		toAddress = "email"
	}
	if len(userName) == 0 {
		userName = "username"
	}
	return NewPasswordRepository(client, userCollection, passwordCollection, historyCollectionName, key, "password", userId, "email", userName, changedTimeName, failCountName, "", "timestamp")
}

func NewPasswordRepositoryByConfig(client *firestore.Client, userCollectionName, passwordCollectionName, historyCollectionName string, key string, c p.PasswordSchemaConfig) *PasswordRepository {
	return NewPasswordRepository(client, userCollectionName, passwordCollectionName, historyCollectionName, key, c.UserId, c.Password, c.ToAddress, c.Username, c.ChangedTime, c.FailCount, c.ChangedBy, c.Timestamp)
}

func NewPasswordRepository(client *firestore.Client, userCollectionName, passwordCollectionName, historyCollectionName, key string, userId, passwordName, toAddress, userName, passwordModifiedTimeName, failCountName, changedByName, timestampName string) *PasswordRepository {
	passwordCollection := client.Collection(passwordCollectionName)
	historyCollection := client.Collection(historyCollectionName)
	userCollection := passwordCollection
	if passwordCollectionName != userCollectionName {
		userCollection = client.Collection(userCollectionName)
	}
	if len(passwordName) == 0 {
		passwordName = "password"
	}
	if len(toAddress) == 0 {
		toAddress = "email"
	}
	if len(userName) == 0 {
		userName = "userName"
	}
	return &PasswordRepository{
		Client:             client,
		UserCollection:     userCollection,
		PasswordCollection: passwordCollection,
		HistoryCollection:  historyCollection,
		Key:                key,
		IdName:             userId,
		ToAddressName:      toAddress,
		PasswordName:       passwordName,
		ChangedTimeName:    passwordModifiedTimeName,
		FailCountName:      failCountName,
		Username:           userName,
		ChangedByName:      changedByName,
		TimestampName:      timestampName,
	}
}

func (r *PasswordRepository) GetUserId(ctx context.Context, userName string) (string, error) {
	docs, err := r.UserCollection.Where(r.Username, "==", userName).Limit(1).Documents(ctx).GetAll()
	if err != nil {
		return "", err
	}
	if len(docs) == 0 {
		return "", nil
	}

	return docs[0].Ref.ID, nil
}

func (r *PasswordRepository) GetUser(ctx context.Context, usernameOrEmail string) (string, string, string, string, error) {
	docs, er0 := r.UserCollection.Where(r.Username, "==", usernameOrEmail).Limit(1).Documents(ctx).GetAll()
	if er0 != nil {
		return "", "", "", "", er0
	}
	if len(docs) == 0 {
		docs, er1 := r.UserCollection.Where(r.ToAddressName, "==", usernameOrEmail).Limit(1).Documents(ctx).GetAll()
		if er1 != nil {
			return "", "", "", "", er1
		}
		if len(docs) == 0 {
			return "", "", "", "", nil
		}
	}
	doc := docs[0]
	userId := doc.Ref.ID

	userName, er2 := doc.DataAt(r.Username)
	if er2 != nil {
		return "", "", "", "", er2
	}

	email, er3 := doc.DataAt(r.ToAddressName)
	if er3 != nil {
		return "", "", "", "", er3
	}

	if strings.Compare(r.UserCollection.ID, r.PasswordCollection.ID) == 0 {
		password, er4 := doc.DataAt(r.PasswordName)
		if er4 != nil {
			return "", "", "", "", er4
		}
		return userId, userName.(string), email.(string), password.(string), nil
	}

	pass, er5 := r.PasswordCollection.Doc(userId).Get(ctx)
	if er5 != nil {
		if strings.Contains(er5.Error(), "NotFound") {
			return userId, userName.(string), email.(string), "", nil
		}
		return "", "", "", "", er5
	}
	password, er6 := pass.DataAt(r.PasswordName)
	return userId, userName.(string), email.(string), password.(string), er6
}

func (r *PasswordRepository) Update(ctx context.Context, userId string, newPassword string) (int64, error) {
	pass := make(map[string]interface{})
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
	_, err := r.PasswordCollection.Doc(userId).Set(ctx, pass, firestore.MergeAll)
	if err != nil {
		return 0, err
	}
	return 1, nil
}
func (r *PasswordRepository) UpdateWithCurrentPassword(ctx context.Context, userId string, currentPassword, newPassword string) (int64, error) {
	err := r.Client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		pass := make(map[string]interface{})
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
		err1 := tx.Set(r.PasswordCollection.Doc(userId), pass, firestore.MergeAll)
		if err1 != nil {
			return err1
		}

		history := make(map[string]interface{})
		history[r.IdName] = userId
		history[r.PasswordName] = currentPassword
		history[r.TimestampName] = time.Now()
		return tx.Create(r.HistoryCollection.NewDoc(), history)
	})
	if err != nil {
		return 0, err
	}
	return 1, nil
}

func (r *PasswordRepository) GetHistory(ctx context.Context, userId string, max int) ([]string, error) {
	history := make([]string, 0)
	iter := r.HistoryCollection.Where(r.IdName, "==", userId).OrderBy(r.TimestampName, firestore.Desc).Limit(max).Offset(1).Documents(ctx)
	defer iter.Stop()
	result, err := iter.Next()
	if err == iterator.Done {
		return history, nil
	}
	if err != nil {
		return history, err
	}
	rawStatus := result.Data()
	if rawStatus == nil {
		return history, fmt.Errorf("user history not found")
	}
	if password, ok := rawStatus[r.PasswordName]; ok {
		if p, k := password.(string); k {
			history = append(history, p)
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
