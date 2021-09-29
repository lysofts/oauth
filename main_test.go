package auth

import (
	"context"
	"testing"

	databaseutils "github.com/lysofts/database-utils"
	"github.com/lysofts/database-utils/utils"
)

var testCollection utils.DatabaseTable = "test_users"

func initAuth() *Auth {
	ctx := context.Background()
	db := databaseutils.NewDatabase(databaseutils.MONGO)
	a := NewAuth(ctx, &db, testCollection)
	return a
}

func TestAuth_SignUp(t *testing.T) {
	a := initAuth()
	fName := "test"
	lName := "test2"

	type args struct {
		ctx   context.Context
		input SignUpInput
	}
	tests := []struct {
		name    string
		args    args
		wantNil bool
		wantErr bool
	}{
		{
			name: "sad invalid input provided",
			args: args{
				ctx: a.ctx,
				input: SignUpInput{
					FirstName: fName,
				},
			},
			wantNil: true,
			wantErr: true,
		},
		{
			name: "happy, signup user",
			args: args{
				ctx: a.ctx,
				input: SignUpInput{
					FirstName: fName,
					LastName:  lName,
					Email:     "test@test.com",
					Phone:     "0708113456",
					Password:  "1234",
				},
			},
			wantNil: false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := a.SignUp(tt.args.ctx, tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Auth.SignUp() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if got != nil && tt.wantNil {
				t.Errorf("Auth.SignUp() = %v, wantNil %v", got, tt.wantNil)
				return
			}

			if got != nil {
				_, err = a.db.Delete(a.ctx, testCollection, map[string]interface{}{"_id": got.UID})
				if err != nil {
					t.Errorf("error, unable to delete test user: %v", err)
					return
				}
			}
		})
	}
}

func TestAuth_Login(t *testing.T) {
	a := initAuth()
	type args struct {
		ctx   context.Context
		input LoginInput
	}
	validEmail := "test@email.com"
	validPass := "1234"

	invalidEmail := "test@mail.com"
	invalidPass := "12345"

	userData := SignUpInput{
		Email:     validEmail,
		Phone:     "0711223344",
		FirstName: "test",
		LastName:  "test",
		Password:  validPass,
	}

	user, err := a.SignUp(a.ctx, userData)
	if err != nil {
		t.Errorf("error, unable to create test user: %v", err)
		return
	}
	tests := []struct {
		name    string
		args    args
		wantNil bool
		wantErr bool
	}{
		{
			name: "invalid email",
			args: args{
				ctx: a.ctx,
				input: LoginInput{
					Email:    invalidEmail,
					Password: "1234",
				},
			},
			wantNil: true,
			wantErr: true,
		},
		{
			name: "invalid password",
			args: args{
				ctx: a.ctx,
				input: LoginInput{
					Email:    "test@email.com",
					Password: invalidPass,
				},
			},
			wantNil: true,
			wantErr: true,
		},
		{
			name: "valid email and password",
			args: args{
				ctx: a.ctx,
				input: LoginInput{
					Email:    validEmail,
					Password: validPass,
				},
			},
			wantNil: false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := a.Login(tt.args.ctx, tt.args.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Auth.Login() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && tt.wantNil {
				t.Errorf("Auth.Login() = %v, wantNil %v", got, tt.wantNil)
				return
			}
		})
	}

	_, err = a.db.Delete(a.ctx, testCollection, map[string]interface{}{"_id": user.UID})
	if err != nil {
		t.Errorf("error, unable to delete test user: %v", err)
		return
	}
}
