package auth

import (
	"context"
	"testing"

	databaseutils "github.com/lysofts/database-utils"
)

const UserCollectionName = "test_users"

func TestHashPassword(t *testing.T) {
	type args struct {
		password string
	}
	tests := []struct {
		name    string
		args    args
		wantNil bool
		wantErr bool
	}{
		{
			name:    "happy: hashed password",
			args:    args{password: "1234"},
			wantNil: false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HashPassword(tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && tt.wantNil {
				t.Errorf("HashPassword() = %v, wantNil %v", got, tt.wantNil)
			}
		})
	}
}

func TestVerifyPassword(t *testing.T) {
	hashed, err := HashPassword("1234")
	if err != nil {
		t.Error("unable to hash test password")
		return
	}
	type args struct {
		userPassword     string
		providedPassword string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{

		{
			name: "happy: passwords matched",
			args: args{
				userPassword:     *hashed,
				providedPassword: "1234",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "sad: passwords did not match",
			args: args{
				userPassword:     *hashed,
				providedPassword: "12345",
			},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyPassword(tt.args.userPassword, tt.args.providedPassword)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	ctx := context.Background()

	db := databaseutils.NewDatabase(databaseutils.MONGO)

	auth := NewAuth(ctx, &db, UserCollectionName)

	//create a user
	user, err := auth.SignUp(ctx, SignUpInput{
		Email:     "test23@mail.com",
		FirstName: "Rick",
		Password:  "1234",
		Phone:     "0708113457",
	})

	if err != nil {
		t.Errorf("unable to create test user: %v", err)
		return
	}

	type args struct {
		signedToken string
	}
	tests := []struct {
		name    string
		args    args
		wantNil bool
		wantErr bool
	}{
		{
			name:    "happy validated token",
			args:    args{signedToken: user.Token},
			wantNil: false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateToken(tt.args.signedToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && tt.wantNil {
				t.Errorf("ValidateToken() = %v, wantNil %v", got, tt.wantNil)
			}
		})
	}

	query := map[string]string{
		"_id": user.UID,
	}
	_, err = db.Delete(ctx, UserCollectionName, query)
	if err != nil {
		t.Errorf("unable to delete test user, %v", err)
		return
	}
}
