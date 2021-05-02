package elasticsearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	p "github.com/core-go/password"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esapi"
	"github.com/elastic/go-elasticsearch/v7/esutil"
	"time"
)

type PasswordRepository struct {
	Client            *elasticsearch.Client
	UserIndexName     string
	PasswordIndexName string
	Key               string // User Id from context
	PasswordName      string
	ToAddressName     string
	ChangedTimeName   string
	FailCountName     string
	UserName          string
	ChangedByName     string
}

func NewPasswordRepositoryByConfig(db *elasticsearch.Client, userIndexName string, passwordIndexName string, key string, c p.PasswordSchemaConfig) *PasswordRepository {
	return NewPasswordRepository(db, userIndexName, passwordIndexName, key, c.Password, c.ToAddress, c.ChangedTime, c.FailCount, c.UserName, c.ChangedBy)
}

func NewPasswordRepository(db *elasticsearch.Client, userIndexName string, passwordIndexName string, key string, passwordName, emailName, userName, passwordModifiedTimeName, failCountName, changedByName string) *PasswordRepository {
	return &PasswordRepository{
		Client:            db,
		UserIndexName:     userIndexName,
		PasswordIndexName: passwordIndexName,
		ToAddressName:     emailName,
		PasswordName:      passwordName,
		ChangedTimeName:   passwordModifiedTimeName,
		FailCountName:     failCountName,
		UserName:          userName,
		ChangedByName:     changedByName,
	}
}

func (r *PasswordRepository) GetUserId(ctx context.Context, userName string) (string, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"match": map[string]interface{}{
					r.UserName: userName,
				},
			},
		},
	}
	res := make(map[string]interface{})
	ok, err := findOneAndDecode(ctx, r.Client, []string{r.UserIndexName}, query, &res)
	if !ok || err != nil {
		return "", err
	}
	return res["_id"].(string), nil
}

func (r *PasswordRepository) GetUser(ctx context.Context, userNameOrEmail string) (userID, userName, toAddressName, passwordName string, err error) {
	userQuery := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{"term": map[string]interface{}{r.UserName: userNameOrEmail}},
					{"term": map[string]interface{}{r.ToAddressName: userNameOrEmail}},
				},
				"minimum_should_match": 1,
			},
		},
	}
	user := make(map[string]interface{})
	ok, err := findOneAndDecode(ctx, r.Client, []string{r.UserIndexName}, userQuery, &user)
	if !ok || err != nil {
		return "", "", "", "", err
	}
	userID = user["_id"].(string)

	pass := make(map[string]interface{})
	ok, err = findOneByIdAndDecode(ctx, r.Client, r.PasswordIndexName, userID, &pass)
	if !ok || err != nil {
		return "", "", "", "", err
	}
	return userID, user[r.UserName].(string), user[r.ToAddressName].(string), pass[r.PasswordName].(string), nil
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
	req := esapi.UpdateRequest{
		Index:      r.PasswordIndexName,
		DocumentID: userId,
		Body:       esutil.NewJSONReader(pass),
		Refresh:    "true",
	}
	res, err := req.Do(ctx, r.Client)
	if err != nil {
		return -1, err
	}
	defer res.Body.Close()
	if res.IsError() {
		return -1, fmt.Errorf("document ID not exists in the index")
	}

	var temp map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&temp)
	if err != nil {
		return -1, err
	}

	successful := int64(temp["_shards"].(map[string]interface{})["successful"].(float64))
	return successful, nil
}

func (r *PasswordRepository) UpdateWithCurrentPassword(ctx context.Context, userId string, currentPassword, newPassword string) (int64, error) {
	return r.Update(ctx, userId, newPassword)
}

func (r *PasswordRepository) GetHistory(ctx context.Context, userId string, max int) ([]string, error) {
	a := make([]string, 0)
	return a, nil
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
func findOneAndDecode(ctx context.Context, client *elasticsearch.Client, index []string, query map[string]interface{}, result interface{}) (bool, error) {
	req := esapi.SearchRequest{
		Index:          index,
		Body:           esutil.NewJSONReader(query),
		TrackTotalHits: true,
		Pretty:         true,
	}
	res, err := req.Do(ctx, client)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return false, errors.New("response error")
	} else {
		var r map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
			return false, err
		} else {
			hits := r["hits"].(map[string]interface{})["hits"].([]interface{})
			total := int(r["hits"].(map[string]interface{})["total"].(map[string]interface{})["value"].(float64))
			if total >= 1 {
				if err := json.NewDecoder(esutil.NewJSONReader(hits[0])).Decode(&result); err != nil {
					return false, err
				}
				return true, nil
			}
			return false, nil
		}
	}
}
func findOneByIdAndDecode(ctx context.Context, client *elasticsearch.Client, indexName string, documentID string, result interface{}) (bool, error) {
	req := esapi.GetRequest{
		Index:      indexName,
		DocumentID: documentID,
	}
	res, err := req.Do(ctx, client)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return false, errors.New("response error")
	} else {
		var r map[string]interface{}
		if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
			return false, err
		} else {
			if err := json.NewDecoder(esutil.NewJSONReader(r["_source"])).Decode(&result); err != nil {
				return false, err
			}
			return true, nil
		}
	}
}
