package auth

//LoginInput is the data required to login a user
type LoginInput struct {
	Email    string `json:"email,omitempty" validate:"required"`
	Password string `json:"password,omitempty" validate:"required"`
}

//SignUpInput is the data required to login a user
type SignUpInput struct {
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Phone     string `json:"phone,omitempty" validate:"required"`
	Email     string `json:"email,omitempty" validate:"required"`
	Password  string `json:"password,omitempty" validate:"required"`
}
