package auth

//AuthResponse the response from login n sign up
type AuthResponse struct {
	UID          string `json:"uid,omitempty"`
	FirstName    string `json:"firstName,omitempty"`
	LastName     string `json:"lastName,omitempty"`
	Email        string `json:"email,omitempty"`
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}
