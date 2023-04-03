package auth

import (
	"api/src/common"
	"api/src/user"
	"database/sql"

	"github.com/lib/pq"
)

var updateQuery = `
UPDATE users
SET password = $2
WHERE id = $1
RETURNING *`

func (r *AuthSqlxRepo) ChangePass(userId uint, newPass string) (*user.User, error) {
	var updatedUser user.User
	if err := r.db.QueryRowx(updateQuery, userId, newPass).StructScan(&updatedUser); err != nil {
		if err == sql.ErrNoRows {
			return nil, common.ErrNotFound
		}

		if ok := err.(*pq.Error).Code == "23505"; ok {
			return nil, common.ErrDuplicate
		}

		return nil, common.InternalError
	}
	return &updatedUser, nil
}
