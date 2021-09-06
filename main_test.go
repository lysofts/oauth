package auth

import (
	"context"
	"testing"

	database "github.com/lysofts/database-utils/mongo_db"
	"go.mongodb.org/mongo-driver/bson"
)

func initializeAuth() (context.Context, *database.Database) {
	ctx := context.Background()
	db := database.New(ctx, "test_users")
	return ctx, db
}

func TestAuth_SignUp(t *testing.T) {
	ctx, db := initializeAuth()
	a := NewAuth(ctx, db)

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
				ctx: ctx,
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
				ctx: ctx,
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
				_, err = db.Delete(ctx, bson.M{"_id": got.UID})
				if err != nil {
					t.Errorf("error, unable to delete test user: %v", err)
					return
				}
			}
		})
	}
}

func TestAuth_Login(t *testing.T) {
	ctx, db := initializeAuth()
	a := NewAuth(ctx, db)
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

	user, err := a.SignUp(ctx, userData)
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
				ctx: ctx,
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
				ctx: ctx,
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
				ctx: ctx,
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

	_, err = db.Delete(ctx, bson.M{"_id": user.UID})
	if err != nil {
		t.Errorf("error, unable to delete test user: %v", err)
		return
	}
}
