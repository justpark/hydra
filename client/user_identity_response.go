package client

type UserIdentityResponse struct {
	UserId    string `json:"id"`
	Name      string `json:"name"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	IsManaged bool   `json:"is_managed"`
}
